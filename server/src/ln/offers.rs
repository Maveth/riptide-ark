//! Authenticated live relay for wallet-owned offers. No signing keys or
//! preimages are entrusted to this service. Queues and pending work are bounded.

use std::collections::HashMap;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context};
use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::hex::{DisplayHex, FromHex};
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

/// BOLT11 the existing hold plugin can parse. The signature is only so that
/// parser accepts it. The payment hash and secret are what the HTLC must match.
fn hold_plugin_invoice(
	network: bitcoin::Network, node_id: bitcoin::secp256k1::PublicKey,
	hash: &ark::lightning::PaymentHash, amount_msat: u64, min_cltv: u64,
	created_at: Duration, expiry: Duration,
) -> anyhow::Result<String> {
	use bitcoin::secp256k1::{Secp256k1, SecretKey};
	use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret, RouteHint, RouteHintHop, RoutingFees};
	let currency = match network {
		bitcoin::Network::Bitcoin => Currency::Bitcoin,
		bitcoin::Network::Testnet => Currency::BitcoinTestnet,
		bitcoin::Network::Signet => Currency::Signet,
		bitcoin::Network::Regtest => Currency::Regtest,
		other => anyhow::bail!("no hold invoice currency for {other}"),
	};
	let mut engine = HmacEngine::<sha256::Hash>::new(b"Paperclip XBT BOLT12 hold invoice key v1");
	engine.input(hash.as_ref());
	let secret = SecretKey::from_slice(&Hmac::<sha256::Hash>::from_engine(engine).to_byte_array())
		.context("hold invoice key")?;
	let secp = Secp256k1::new();
	let invoice = InvoiceBuilder::new(currency)
		.description("Ark".into())
		.payment_hash(hash.to_sha256_hash())
		.payment_secret(PaymentSecret(bolt12_receive::hold_path_id(hash.as_ref())))
		.amount_milli_satoshis(amount_msat)
		.duration_since_epoch(created_at)
		.expiry_time(expiry)
		.min_final_cltv_expiry_delta(min_cltv)
		.private_route(RouteHint(vec![RouteHintHop {
			src_node_id: node_id,
			short_channel_id: 1,
			fees: RoutingFees { base_msat: 0, proportional_millionths: 0 },
			cltv_expiry_delta: 40,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}]))
		.build_signed(|msg| secp.sign_ecdsa_recoverable(msg, &secret))
		.context("hold invoice")?;
	Ok(invoice.to_string())
}

struct Request {
	bytes: Vec<u8>,
	response: oneshot::Sender<Result<String, String>>,
}

#[derive(Default)]
pub struct OfferRelay {
	routes: parking_lot::Mutex<HashMap<[u8; 32], (u64, mpsc::Sender<Request>)>>,
	serial: std::sync::atomic::AtomicU64,
}

struct Session {
	relay: Arc<OfferRelay>,
	ids: Vec<[u8; 32]>,
	serial: u64,
}

impl Drop for Session {
	fn drop(&mut self) {
		let mut routes = self.relay.routes.lock();
		for id in &self.ids {
			if routes.get(id).is_some_and(|(serial, _)| *serial == self.serial) {
				routes.remove(id);
			}
		}
	}
}

fn offer_keys(offer: &Offer) -> Vec<[u8; 32]> {
	let mut keys = vec![
		sha256::Hash::hash(&offer.encode()).to_byte_array(),
		offer.id().0,
	];
	if let Ok(fields) = bolt12_receive::offer_fields_id(&offer.encode()) {
		keys.push(fields);
	}
	keys.sort_unstable();
	keys.dedup();
	keys
}

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
			let ids = offer_keys(&offer);
			let serial = relay.serial.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
			let (tx, mut rx) = mpsc::channel(8);
			let registered = {
				let mut routes = relay.routes.lock();
				let new_keys = ids.iter().filter(|id| !routes.contains_key(*id)).count();
				if routes.len() + new_keys > 1024 {
					Err(tonic::Status::resource_exhausted("offer relay full"))
				} else {
					for id in &ids { routes.insert(*id, (serial, tx.clone())); }
					Ok(())
				}
			};
			registered?;
			let _session = Session { relay, ids, serial };
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
				let response = match tokio::time::timeout(Duration::from_secs(20), input.message()).await {
					Ok(Ok(Some(response))) => response,
					Ok(Ok(None)) => break,
					Ok(Err(error)) => Err(error)?,
					Err(_) => {
						refuse(request.response, "request timed out");
						continue;
					},
				};
				if response.request_id != request_id {
					refuse(request.response, "request id mismatch");
					continue;
				}
				if !response.error.is_empty() {
					tracing::info!("BOLT12 wallet refused: {}", response.error);
					let _ = request.response.send(Err(response.error));
					continue;
				}
				if response.invoice.len() > 32_768 {
					refuse(request.response, "invoice too large");
					continue;
				}
				let invoice = match Invoice::from_str(&response.invoice) {
					Ok(invoice) => invoice,
					Err(_) => {
						refuse(request.response, "invalid invoice");
						continue;
					},
				};
				let Invoice::Bolt12(ref bolt12) = invoice else {
					refuse(request.response, "expected BOLT12 invoice");
					continue;
				};
				match bolt12_receive::matches_request(bolt12, &request.bytes) {
					Ok(true) => {},
					Ok(false) => {
						refuse(request.response, "invoice does not match request");
						continue;
					},
					Err(_) => {
						refuse(request.response, "invalid invoice request");
						continue;
					},
				}
				// Registration must finish before an invoice becomes payable.
				let subscription = match db.read(async |t| t.get_htlc_subscription_by_payment_hash(invoice.payment_hash()).await).await {
					Ok(Some(subscription)) => subscription,
					Ok(None) => {
						refuse(request.response, "receive not registered");
						continue;
					},
					Err(_) => {
						refuse(request.response, "receive unavailable");
						continue;
					},
				};
				if subscription.invoice != invoice || subscription.status != LightningHtlcSubscriptionStatus::Created {
					refuse(request.response, "receive unavailable");
					continue;
				}
				let _ = request.response.send(Ok(response.invoice));
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

	fn route_for(&self, bytes: &[u8]) -> Option<mpsc::Sender<Request>> {
		let mut keys = Vec::new();
		if let Ok(id) = bolt12_receive::offer_fields_id(bytes) { keys.push(id); }
		if let Ok(offer) = bolt12_receive::request_offer(bytes) {
			keys.extend(offer_keys(&offer));
		}
		let routes = self.routes.lock();
		keys.into_iter().find_map(|key| routes.get(&key).map(|(_, tx)| tx.clone()))
	}

	async fn run_node(self: Arc<Self>, node: NodeHandle) -> anyhow::Result<()> {
		let (tx, rx) = mpsc::channel(64);
		let mut stream = node.hold_rpc.clone().context("hold unavailable")?
			.onion_messages(ReceiverStream::new(rx)).await?.into_inner();
		let semaphore = Arc::new(Semaphore::new(64));
		let mut replies = tokio::task::JoinSet::new();
		while let Some(message) = stream.message().await? {
			while replies.try_join_next().is_some() {}
			let route = message.invoice_request.as_deref().and_then(|bytes| self.route_for(bytes));
			let claimed = route.is_some();
			if message.invoice_request.is_some() {
				tracing::info!(claimed, "BOLT12 invoice request");
			}
			tx.send(hold::OnionMessageResponse { id: message.id, action: if claimed { 1 } else { 0 } }).await?;
			let (Some(route), Some(bytes), Some(reply_path)) = (route, message.invoice_request, message.reply_blindedpath) else { continue; };
			let Ok(permit) = semaphore.clone().try_acquire_owned() else {
				replies.spawn(reply_with(node.clone(), reply_path, Err("offer busy".into())));
				continue;
			};
			let (response, result) = oneshot::channel();
			if route.try_send(Request { bytes, response }).is_err() {
				replies.spawn(reply_with(node.clone(), reply_path, Err("offer unavailable".into())));
				continue;
			}
			let node = node.clone();
			replies.spawn(async move {
				let _permit = permit;
				let answer = match tokio::time::timeout(Duration::from_secs(25), result).await {
					Ok(Ok(answer)) => answer,
					Ok(Err(_)) => Err("offer unavailable".into()),
					Err(_) => Err("request timed out".into()),
				};
				reply_with(node, reply_path, answer).await;
			});
		}
		Ok(())
	}
}

async fn reply_with(
	node: NodeHandle, path: hold::onion_message::ReplyBlindedPath, answer: Result<String, String>,
) {
	let (kind, result) = match answer {
		Ok(invoice) => ("invoice", send_reply(node, path, invoice).await),
		Err(error) => {
			tracing::info!("BOLT12 refusal: {error}");
			("refusal", send_refusal(node, path, error).await)
		},
	};
	match result {
		Ok(()) => tracing::info!("BOLT12 {kind} sent"),
		Err(error) => tracing::warn!("BOLT12 {kind} failed: {error:#}"),
	}
}

fn refuse(response: oneshot::Sender<Result<String, String>>, reason: &str) {
	tracing::warn!("BOLT12 invoice refused: {reason}");
	let _ = response.send(Err(reason.to_string()));
}

async fn send_refusal(
	mut node: NodeHandle, path: hold::onion_message::ReplyBlindedPath, message: String,
) -> anyhow::Result<()> {
	let (relay, blinded) = outgoing_path(&mut node, path).await?;
	let (key, packet) = bolt12_receive::invoice_error_reply(relay, blinded, message)?;
	inject_reply(&mut node, key, packet).await
}

async fn reply_path(
	node: &mut NodeHandle, path: hold::onion_message::ReplyBlindedPath,
) -> anyhow::Result<(PublicKey, lightning::blinded_path::message::BlindedMessagePath)> {
	ensure!(!path.hops.is_empty() && path.hops.len() <= 20, "invalid reply path length");
	let first = if let Some(id) = path.first_node_id {
		PublicKey::from_slice(&id)?
	} else {
		let scid = path.first_scid.context("missing introduction node")?;
		let direction = path.first_scid_dir.context("missing introduction direction")?;
		ensure!(direction <= 1, "invalid introduction direction");
		let channels = node.rpc.list_channels(cln_rpc::ListchannelsRequest {
			short_channel_id: Some(scid), source: None, destination: None,
		}).await?.into_inner();
		let channel = channels.channels.into_iter()
			.find(|c| u64::from(c.channel_flags & 1) == direction)
			.context("unknown introduction channel")?;
		PublicKey::from_slice(&channel.source)?
	};
	let blinding = PublicKey::from_slice(&path.first_path_key.context("missing path key")?)?;
	let hops = path.hops.into_iter().map(|hop| Ok(BlindedHop {
		blinded_node_id: PublicKey::from_slice(&hop.blinded_node_id.context("missing blinded node")?)?,
		encrypted_payload: hop.encrypted_recipient_data.context("missing recipient data")?,
	})).collect::<anyhow::Result<Vec<_>>>()?;
	Ok((node.pubkey, BlindedMessagePath::from_blinded_path(first, blinding, hops)))
}

async fn send_reply(mut node: NodeHandle, path: hold::onion_message::ReplyBlindedPath, invoice: String) -> anyhow::Result<()> {
	let Invoice::Bolt12(invoice) = Invoice::from_str(&invoice)? else { anyhow::bail!("expected BOLT12 invoice"); };
	let (relay, blinded) = outgoing_path(&mut node, path).await?;
	let (key, message) = bolt12_receive::invoice_reply(relay, blinded, invoice)?;
	inject_reply(&mut node, key, message).await
}

/// The socket is a root-owned proxy of Core Lightning's JSON-RPC, created so
/// this process can ask the node to peel one reply hop. The proxy does not
/// widen what the Ark server can already do over its CLN credentials.
const CLN_RPC_SOCKET: &str = "/var/lib/paperclip-asp/cln-lightning-rpc";

async fn inject_reply(node: &mut NodeHandle, key: PublicKey, message: Vec<u8>) -> anyhow::Result<()> {
	let bytes = message.len();
	node.rpc.inject_onion_message(cln_rpc::InjectonionmessageRequest {
		path_key: key.serialize().to_vec(), message,
	}).await?;
	tracing::info!(bytes, "BOLT12 reply onion injected");
	Ok(())
}

/// If the payer's reply path starts here, peel that hop with the node key and
/// continue from the next node under the next path key. The onion built after
/// this is a fresh packet for that next node, not the tail of the hop we peeled.
async fn outgoing_path(
	node: &mut NodeHandle, path: hold::onion_message::ReplyBlindedPath,
) -> anyhow::Result<(PublicKey, BlindedMessagePath)> {
	let (relay, blinded) = reply_path(node, path).await?;
	let starts_here = matches!(
		blinded.introduction_node(),
		lightning::blinded_path::IntroductionNode::NodeId(id) if *id == relay,
	);
	if !starts_here {
		tracing::info!(hops = blinded.blinded_hops().len(), "BOLT12 reply path starts at a peer");
		return Ok((relay, blinded));
	}
	let hops = blinded.blinded_hops();
	// One hop whose introduction is this node means this node is the final
	// recipient of the reply. Injecting it delivers the invoice here. A longer
	// path that starts here is peeled and sent on to the next node.
	if hops.len() < 2 {
		tracing::info!(hops = hops.len(), "BOLT12 reply path is delivered here");
		return Ok((relay, blinded));
	}
	let peeled = peel_our_hop(node, &hops[0].encrypted_payload, blinded.blinding_point()).await?;
	ensure!(peeled.node != relay, "reply hop loops at the relay");
	let rest = hops[1..].iter().map(|hop| BlindedHop {
		blinded_node_id: hop.blinded_node_id,
		encrypted_payload: hop.encrypted_payload.clone(),
	}).collect();
	tracing::info!(hops = hops.len(), "BOLT12 reply path peeled at the relay");
	Ok((relay, BlindedMessagePath::from_blinded_path(peeled.node, peeled.key, rest)))
}

struct PeeledHop {
	node: PublicKey,
	key: PublicKey,
}

async fn peel_our_hop(node: &mut NodeHandle, encrypted: &[u8], path_key: PublicKey) -> anyhow::Result<PeeledHop> {
	let result = cln_rpc_call("decryptencrypteddata", serde_json::json!({
		"encrypted_data": encrypted.to_lower_hex_string(),
		"path_key": path_key.to_string(),
	})).await.context("peeling our reply hop")?;
	let body = result.get("decryptencrypteddata").unwrap_or(&result);
	let decrypted = Vec::<u8>::from_hex(body.get("decrypted").and_then(|v| v.as_str()).context("missing decrypted hop")?)?;
	let derived = PublicKey::from_str(body.get("next_path_key").and_then(|v| v.as_str()).context("missing next path key")?)?;
	let records = tlv_records(&decrypted).context("reply hop tlv")?;
	let key = records.get(&8).map(|bytes| PublicKey::from_slice(bytes)).transpose()?.unwrap_or(derived);
	let next = if let Some(bytes) = records.get(&4) {
		PublicKey::from_slice(bytes)?
	} else if let Some(scid) = records.get(&2) {
		next_node_from_scid(node, scid).await?
	} else {
		anyhow::bail!("reply hop names no next node");
	};
	Ok(PeeledHop { node: next, key })
}

async fn next_node_from_scid(node: &mut NodeHandle, scid: &[u8]) -> anyhow::Result<PublicKey> {
	ensure!(scid.len() == 8, "reply hop channel id length");
	let value = u64::from_be_bytes(scid.try_into().expect("length checked"));
	let formatted = format!("{}x{}x{}", value >> 40, (value >> 16) & 0xffffff, value & 0xffff);
	let channels = node.rpc.list_channels(cln_rpc::ListchannelsRequest {
		short_channel_id: Some(formatted), source: None, destination: None,
	}).await?.into_inner();
	let ours = node.pubkey.serialize();
	for channel in &channels.channels {
		if channel.source.as_slice() == ours.as_slice() {
			return Ok(PublicKey::from_slice(&channel.destination)?);
		}
	}
	for channel in &channels.channels {
		if channel.destination.as_slice() == ours.as_slice() {
			return Ok(PublicKey::from_slice(&channel.source)?);
		}
	}
	anyhow::bail!("reply hop channel is not ours")
}

fn tlv_records(mut data: &[u8]) -> anyhow::Result<std::collections::HashMap<u64, Vec<u8>>> {
	let mut records = std::collections::HashMap::new();
	while !data.is_empty() {
		let (typ, used) = read_bigsize(data).context("tlv type")?;
		data = &data[used..];
		let (len, used) = read_bigsize(data).context("tlv length")?;
		data = &data[used..];
		let len = usize::try_from(len)?;
		ensure!(data.len() >= len, "tlv value overruns the hop");
		records.insert(typ, data[..len].to_vec());
		data = &data[len..];
	}
	Ok(records)
}

fn read_bigsize(data: &[u8]) -> Option<(u64, usize)> {
	let first = *data.first()?;
	if first < 0xfd {
		return Some((u64::from(first), 1));
	}
	if first == 0xfd && data.len() >= 3 {
		return Some((u64::from(u16::from_be_bytes([data[1], data[2]])), 3));
	}
	if first == 0xfe && data.len() >= 5 {
		let bytes: [u8; 4] = data[1..5].try_into().ok()?;
		return Some((u64::from(u32::from_be_bytes(bytes)), 5));
	}
	if first == 0xff && data.len() >= 9 {
		let bytes: [u8; 8] = data[1..9].try_into().ok()?;
		return Some((u64::from_be_bytes(bytes), 9));
	}
	None
}

async fn cln_rpc_call(method: &str, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	let mut stream = tokio::net::UnixStream::connect(CLN_RPC_SOCKET).await.context("lightning rpc socket")?;
	let request = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
	stream.write_all(format!("{request}\n").as_bytes()).await?;
	let mut buf = Vec::new();
	let mut tmp = [0u8; 8192];
	loop {
		let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tmp)).await.context("lightning rpc timed out")??;
		if read == 0 { break; }
		buf.extend_from_slice(&tmp[..read]);
		if serde_json::from_slice::<serde_json::Value>(&buf).is_ok() { break; }
	}
	let value: serde_json::Value = serde_json::from_slice(&buf).context("lightning rpc response")?;
	if let Some(error) = value.get("error") {
		anyhow::bail!("lightning rpc {method} failed: {error}");
	}
	value.get("result").cloned().context("lightning rpc result")
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
		// The hold plugin only parses BOLT11. Register one with the same hash,
		// amount, and the path id the wallet put in the BOLT12 hop. The payer
		// still pays the BOLT12 invoice. Our records keep that invoice.
		let hold_invoice = hold_plugin_invoice(self.config.network, node.pubkey, &hash, msat, u64::from(u16::from(cltv)), bolt12.created_at(), bolt12.relative_expiry())?;
		// A failed DB commit after injection is recoverable by retrying this exact
		// invoice. Never adopt an invoice that someone else registered for the hash.
		let existing = hold.list(hold::ListRequest { constraint: Some(hold::list_request::Constraint::PaymentHash(hash.to_vec())) }).await?.into_inner();
		if let Some(existing) = existing.invoices.first() {
			ensure!(existing.invoice == hold_invoice && existing.state == 0 && existing.min_cltv_expiry == Some(u64::from(cltv)), "hold invoice conflicts");
		} else {
			hold.inject(hold::InjectRequest { invoice: hold_invoice, min_cltv_expiry: Some(u64::from(cltv)) }).await?;
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
