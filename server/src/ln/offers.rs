//! Authenticated live relay for wallet-owned offers. No signing keys or
//! preimages are entrusted to this service. Queues and pending work are bounded.

use std::collections::HashMap;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{rand, schnorr, PublicKey};
use cln_rpc::plugins::hold;
use lightning::blinded_path::{BlindedHop, message::BlindedMessagePath};
use lightning::util::ser::Writeable;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio_stream::{Stream, wrappers::ReceiverStream};
use server_rpc::protos;
use ark::{bolt12_receive, ProtocolEncoding};
use ark::lightning::{Invoice, Offer};
use crate::database;
use crate::database::ln::LightningHtlcSubscriptionStatus;
use crate::ln::cln::NodeHandle;
use crate::system::RuntimeManager;

pub type OfferStream = Pin<Box<dyn Stream<Item = Result<protos::LightningOfferServer, tonic::Status>> + Send>>;

struct Request {
	bytes: Vec<u8>,
	response: oneshot::Sender<String>,
}

#[derive(Default)]
pub struct OfferRelay {
	routes: parking_lot::Mutex<HashMap<[u8; 32], (u64, mpsc::Sender<Request>)>>,
	serial: std::sync::atomic::AtomicU64,
}

struct Session {
	relay: Arc<OfferRelay>,
	id: [u8; 32],
	serial: u64,
}

impl Drop for Session {
	fn drop(&mut self) {
		let mut routes = self.relay.routes.lock();
		if routes.get(&self.id).is_some_and(|(serial, _)| *serial == self.serial) {
			routes.remove(&self.id);
		}
	}
}

fn offer_id(offer: &Offer) -> [u8; 32] { sha256::Hash::hash(&offer.encode()).to_byte_array() }

impl OfferRelay {
	pub fn serve(self: &Arc<Self>, mut input: tonic::Streaming<protos::LightningOfferClient>, db: database::Db) -> OfferStream {
		let relay = self.clone();
		Box::pin(async_stream::try_stream! {
			let challenge: [u8; 32] = rand::random();
			yield protos::LightningOfferServer { challenge: challenge.to_vec(), ..Default::default() };
			let auth = tokio::time::timeout(Duration::from_secs(10), input.message()).await
				.map_err(|_| tonic::Status::deadline_exceeded("offer authentication timed out"))??
				.ok_or_else(|| tonic::Status::unauthenticated("missing offer authentication"))?;
			if auth.offer.len() > 32_768 { Err(tonic::Status::invalid_argument("offer too large"))?; }
			let offer = Offer::from_str(&auth.offer).map_err(|_| tonic::Status::invalid_argument("invalid offer"))?;
			let key = offer.issuer_signing_pubkey().ok_or_else(|| tonic::Status::invalid_argument("offer requires signing key"))?;
			let signature = schnorr::Signature::from_slice(&auth.challenge_signature)
				.map_err(|_| tonic::Status::unauthenticated("invalid signature"))?;
			let message = bolt12_receive::session_challenge(&offer, &challenge)
				.map_err(|_| tonic::Status::invalid_argument("invalid challenge"))?;
			ark::SECP.verify_schnorr(&signature, &message, &key.x_only_public_key().0)
				.map_err(|_| tonic::Status::unauthenticated("offer ownership proof failed"))?;
			if !offer.offer_features().requires_blake2b_identity() {
				Err(tonic::Status::invalid_argument("offer must require XBT"))?;
			}
			let id = offer_id(&offer);
			let serial = relay.serial.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
			let (tx, mut rx) = mpsc::channel(8);
			let registered = {
				let mut routes = relay.routes.lock();
				if routes.len() >= 1024 && !routes.contains_key(&id) {
					Err(tonic::Status::resource_exhausted("offer relay full"))
				} else {
					routes.insert(id, (serial, tx));
					Ok(())
				}
			};
			registered?;
			let _session = Session { relay, id, serial };
			loop {
				// Each session handles one request at a time. The queue absorbs short bursts.
				let event = tokio::select! {
					r = rx.recv() => Ok(r),
					r = input.message() => match r {
						Ok(None) => Ok(None),
						Ok(Some(_)) => Err(tonic::Status::invalid_argument("unexpected offer response")),
						Err(error) => Err(error),
					},
				};
				let Some(request) = event? else { break; };
				if request.response.is_closed() { continue; }
				let request_id = sha256::Hash::hash(&request.bytes).to_byte_array();
				yield protos::LightningOfferServer {
					request_id: request_id.to_vec(), invoice_request: request.bytes.clone(), ..Default::default()
				};
				let response = tokio::time::timeout(Duration::from_secs(20), input.message()).await
					.map_err(|_| tonic::Status::deadline_exceeded("wallet did not answer offer request"))??;
				let Some(response) = response else { break; };
				if response.request_id != request_id { Err(tonic::Status::invalid_argument("request id mismatch"))?; }
				if !response.error.is_empty() { continue; }
				if response.invoice.len() > 32_768 { Err(tonic::Status::invalid_argument("invoice too large"))?; }
				let invoice = Invoice::from_str(&response.invoice).map_err(|_| tonic::Status::invalid_argument("invalid invoice"))?;
				let Invoice::Bolt12(ref bolt12) = invoice else { Err(tonic::Status::invalid_argument("expected BOLT12"))?; unreachable!() };
				if !bolt12_receive::matches_request(bolt12, &request.bytes).unwrap_or(false) {
					Err(tonic::Status::invalid_argument("invoice does not match request"))?;
				}
				// Registration must finish before an invoice becomes payable.
				let subscription = db.read(async |t| t.get_htlc_subscription_by_payment_hash(invoice.payment_hash()).await).await
					.map_err(|_| tonic::Status::internal("failed to check receive registration"))?
					.ok_or_else(|| tonic::Status::failed_precondition("receive not registered"))?;
				if subscription.invoice != invoice || subscription.status != LightningHtlcSubscriptionStatus::Created {
					Err(tonic::Status::failed_precondition("receive unavailable"))?;
				}
				let _ = request.response.send(response.invoice);
			}
		})
	}

	pub(crate) async fn run(self: Arc<Self>, nodes: Arc<parking_lot::RwLock<Vec<NodeHandle>>>, runtime: RuntimeManager) {
		let _guard = runtime.spawn("BOLT12 offer relay");
		let mut tasks = HashMap::<i64, tokio::task::JoinHandle<()>>::new();
		while !runtime.shutdown_requested() {
			let snapshot = nodes.read().clone();
			tasks.retain(|id, task| {
				if task.is_finished() { return false; }
				if !snapshot.iter().any(|n| n.id == *id && n.hold_rpc.is_some()) { task.abort(); return false; }
				true
			});
			for node in snapshot.into_iter().filter(|n| n.hold_rpc.is_some()) {
				if tasks.contains_key(&node.id) { continue; }
				let relay = self.clone();
				tasks.insert(node.id, tokio::spawn(async move {
					if let Err(error) = relay.run_node(node).await { tracing::warn!("BOLT12 relay disconnected: {error:#}"); }
				}));
			}
			tokio::time::sleep(Duration::from_secs(2)).await;
		}
		for (_, task) in tasks { task.abort(); let _ = task.await; }
	}

	async fn run_node(self: Arc<Self>, node: NodeHandle) -> anyhow::Result<()> {
		let (tx, rx) = mpsc::channel(64);
		let mut stream = node.hold_rpc.clone().context("hold unavailable")?
			.onion_messages(ReceiverStream::new(rx)).await?.into_inner();
		let semaphore = Arc::new(Semaphore::new(64));
		let mut replies = tokio::task::JoinSet::new();
		while let Some(message) = stream.message().await? {
			while replies.try_join_next().is_some() {}
			let route = message.invoice_request.as_deref().and_then(|bytes| bolt12_receive::request_offer(bytes).ok())
				.and_then(|offer| self.routes.lock().get(&offer_id(&offer)).map(|(_, tx)| tx.clone()));
			let claimed = route.is_some();
			tx.send(hold::OnionMessageResponse { id: message.id, action: if claimed { 1 } else { 0 } }).await?;
			let (Some(route), Some(bytes), Some(reply_path)) = (route, message.invoice_request, message.reply_blindedpath) else { continue; };
			let Ok(permit) = semaphore.clone().try_acquire_owned() else { continue; };
			let (response, result) = oneshot::channel();
			if route.try_send(Request { bytes, response }).is_err() { continue; }
			let node = node.clone();
			replies.spawn(async move {
				let _permit = permit;
				if let Ok(Ok(invoice)) = tokio::time::timeout(Duration::from_secs(25), result).await {
					if let Err(error) = send_reply(node, reply_path, invoice).await { tracing::warn!("BOLT12 reply failed: {error:#}"); }
				}
			});
		}
		Ok(())
	}
}

async fn send_reply(mut node: NodeHandle, path: hold::onion_message::ReplyBlindedPath, invoice: String) -> anyhow::Result<()> {
	ensure!(!path.hops.is_empty() && path.hops.len() <= 20, "invalid reply path length");
	let first = if let Some(id) = path.first_node_id {
		PublicKey::from_slice(&id)?
	} else {
		let scid = path.first_scid.context("missing introduction node")?;
		let direction = path.first_scid_dir.context("missing introduction direction")?;
		ensure!(direction <= 1, "invalid introduction direction");
		let channels = node.rpc.list_channels(cln_rpc::ListchannelsRequest { short_channel_id: Some(scid), source: None, destination: None }).await?.into_inner();
		let channel = channels.channels.into_iter().find(|c| u64::from(c.channel_flags & 1) == direction).context("unknown introduction channel")?;
		PublicKey::from_slice(&channel.source)?
	};
	let blinding = PublicKey::from_slice(&path.first_path_key.context("missing path key")?)?;
	let hops = path.hops.into_iter().map(|hop| Ok(BlindedHop {
		blinded_node_id: PublicKey::from_slice(&hop.blinded_node_id.context("missing blinded node")?)?,
		encrypted_payload: hop.encrypted_recipient_data.context("missing recipient data")?,
	})).collect::<anyhow::Result<Vec<_>>>()?;
	let Invoice::Bolt12(invoice) = Invoice::from_str(&invoice)? else { anyhow::bail!("expected BOLT12 invoice"); };
	let path = BlindedMessagePath::from_blinded_path(first, blinding, hops);
	let (key, message) = bolt12_receive::invoice_reply(node.pubkey, path, invoice)?;
	node.rpc.inject_onion_message(cln_rpc::InjectonionmessageRequest { path_key: key.serialize().to_vec(), message }).await?;
	Ok(())
}

impl crate::Server {
	pub(crate) async fn register_bolt12_receive_inner(&self, request: protos::RegisterBolt12ReceiveRequest) -> anyhow::Result<()> {
		ensure!(request.invoice.len() <= 32_768, "invoice too large");
		let invoice = Invoice::from_str(&request.invoice)?;
		let Invoice::Bolt12(ref bolt12) = invoice else { anyhow::bail!("expected BOLT12 invoice"); };
		invoice.require_xbt()?;
		invoice.check_signature()?;
		ensure!(bolt12.chain() == bitcoin::constants::ChainHash::using_genesis_block(self.config.network), "wrong invoice chain");
		let now = std::time::UNIX_EPOCH.elapsed()?;
		ensure!(bolt12.created_at() <= now + Duration::from_secs(30), "invoice created in future");
		ensure!(!invoice.expired_at(now) && bolt12.relative_expiry() <= Duration::from_secs(3600), "invoice expiry outside limits");
		let msat = bolt12.amount_msats();
		ensure!(msat > 0 && msat % 1000 == 0, "invoice must be whole sats");
		let amount = bitcoin::Amount::from_sat(msat / 1000);
		crate::check_max_amount("lightning receive", amount, self.config.max_ln_receive_amount)?;
		let hash = invoice.payment_hash();
		let tab_user = if amount < ark::lightning::lightning_tab_floor() {
			let user = PublicKey::from_slice(request.tab_user_pubkey.as_deref()
				.context("a receive under the dust floor must name the tab key")?)
				.context("invalid tab user pubkey")?;
			let signature = request.tab_signature.as_deref()
				.context("a receive under the dust floor must be signed")?;
			crate::ln::tab::verify_tab_signature(&user, signature, "receive", hash.as_ref())?;
			if self.lightning_tab_is_opted_out(user).await? {
				return badarg!("this key opted out of small Lightning payments");
			}
			Some(user)
		} else {
			if request.tab_user_pubkey.is_some() || request.tab_signature.is_some() {
				return badarg!("a receive of {} sats is a coin, not a tab credit", amount.to_sat());
			}
			crate::check_max_amount("lightning receive", amount, self.config.max_vtxo_amount)?;
			let fee = self.config.fees.lightning_receive.calculate(amount).context("fee overflow")?;
			ark::fees::validate_and_subtract_fee(amount, fee)?;
			None
		};
		let delta = bitcoin_ext::BlockDelta::try_from(request.min_cltv_delta)?;
		ensure!(u16::from(delta) > 0 && delta <= self.config.max_user_invoice_cltv_delta, "CLTV outside limits");
		let cltv = delta.checked_add(self.config.htlc_expiry_delta).context("CLTV overflow")?;
		let node = self.lightning_manager.hold_active_node().context("Lightning relay offline")?;
		ensure!(bolt12.payment_paths().len() == 1, "expected one relay payment path");
		let path = &bolt12.payment_paths()[0];
		ensure!(path.blinded_hops().len() == 1 && path.introduction_node() == &lightning::blinded_path::IntroductionNode::NodeId(node.pubkey), "payment path must terminate at relay");
		ensure!(path.payinfo.cltv_expiry_delta == u16::from(cltv), "payment path CLTV mismatch");
		ensure!(path.payinfo.fee_base_msat == 0 && path.payinfo.fee_proportional_millionths == 0, "unexpected relay fee");
		let mailbox = request.mailbox_id.as_deref().map(ark::mailbox::MailboxIdentifier::deserialize).transpose()?;
		let _guard = self.payment_guards.lock(hash).await;
		ensure!(self.htlc_settler.is_settled(hash).await?.is_none(), "invoice already settled");
		ensure!(self.db.read(async |t| t.get_round_participation_by_unlock_hash(hash.to_sha256_hash()).await).await?.is_none(), "hash collides with unlock hash");
		if let Some(existing) = self.db.read(async |t| t.get_htlc_subscription_by_payment_hash(hash).await).await? {
			ensure!(existing.invoice == invoice && existing.lightning_node_id == node.id, "receive registration conflicts");
			ensure!(existing.status == LightningHtlcSubscriptionStatus::Created, "receive already used or canceled");
			let existing_mailbox = self.db.read(async |t| t.get_lightning_receiver_mailbox_id(hash).await).await?;
			ensure!(existing_mailbox == mailbox, "receive mailbox mismatch");
			if let Some(user) = tab_user.as_ref() {
				let amount_sat = i64::try_from(amount.to_sat())?;
				self.db.write(async |t| t.register_lightning_tab_receive(hash, user, amount_sat).await).await?;
			}
			return Ok(());
		}
		let mut hold = node.hold_rpc.context("hold unavailable")?;
		// A failed DB commit after injection is recoverable by retrying this exact
		// invoice. Never adopt an invoice that someone else registered for the hash.
		let existing = hold.list(hold::ListRequest { constraint: Some(hold::list_request::Constraint::PaymentHash(hash.to_vec())) }).await?.into_inner();
		if let Some(existing) = existing.invoices.first() {
			ensure!(existing.invoice == invoice.to_string() && existing.state == 0 && existing.min_cltv_expiry == Some(u64::from(cltv)), "hold invoice conflicts");
		} else {
			hold.inject(hold::InjectRequest { invoice: invoice.to_string(), min_cltv_expiry: Some(u64::from(cltv)) }).await?;
		}
		let agent = crate::telemetry::current_user_agent();
		let amount_sat = i64::try_from(amount.to_sat())?;
		self.db.write(async |t| {
			t.store_generated_lightning_receive(node.id, &invoice, msat, mailbox.as_ref(), agent.as_deref()).await?;
			if let Some(user) = tab_user.as_ref() {
				t.register_lightning_tab_receive(hash, user, amount_sat).await?;
			}
			Ok(())
		}).await?;
		Ok(())
	}
}
