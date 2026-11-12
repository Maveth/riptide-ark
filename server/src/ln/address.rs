//! Lightning addresses (`name@ark-riptide.maveth.ca`).
//!
//! A payer's wallet fetches `/.well-known/lnurlp/{name}` and then asks the
//! callback for an invoice. Under 1,000 sats the server creates that invoice
//! and credits the tab when it is paid. At 1,000 sats or more the open wallet
//! creates one coin invoice. A later request for that same unpaid amount gets
//! the bolt11 already made. There is no maximum other than the amount this
//! node can receive.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::secp256k1::PublicKey;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::{info, warn};

use ark::lightning::{lightning_tab_message, PaymentHash, Preimage, LIGHTNING_TAB_CHUNK_SAT};

use crate::error::ContextExt;
use crate::Server;

pub const ADDRESS_HOST: &str = "ark-riptide.maveth.ca";
const HTTP_ADDR: &str = "0.0.0.0:3537";
/// Stay under the current receivable side of the bridge.
const MAX_SENDABLE_SAT: u64 = 150_000_000;

struct Inflight {
	/// Bumped when the wallet is asked again, so an older timer cannot
	/// cancel the build that replaced it.
	id: u64,
	amount_sat: u64,
	waiters: Vec<oneshot::Sender<Result<String, String>>>,
}

struct ReadyCoin {
	amount_sat: u64,
	bolt11: String,
	expires_at: std::time::SystemTime,
	payment_hash: Option<PaymentHash>,
}

struct CoinWait {
	wallet: Mutex<HashMap<String, oneshot::Sender<u64>>>,
	/// One build per name. A retry waits on that build instead of starting another.
	inflight: Mutex<HashMap<String, Inflight>>,
	/// The last unpaid invoice. A later request for the same amount gets this bolt11.
	ready: Mutex<HashMap<String, ReadyCoin>>,
}

fn hub() -> &'static CoinWait {
	use std::sync::OnceLock;
	static HUB: OnceLock<CoinWait> = OnceLock::new();
	HUB.get_or_init(|| CoinWait {
		wallet: Mutex::new(HashMap::new()),
		inflight: Mutex::new(HashMap::new()),
		ready: Mutex::new(HashMap::new()),
	})
}

fn ready_invoice(name: &str, amount_sat: u64) -> Option<String> {
	let mut ready = hub().ready.lock();
	let coin = ready.get(name)?;
	let fresh = coin.amount_sat == amount_sat
		&& coin.expires_at > std::time::SystemTime::now();
	if fresh {
		return Some(coin.bolt11.clone());
	}
	ready.remove(name);
	None
}

fn next_inflight_id() -> u64 {
	use std::sync::atomic::{AtomicU64, Ordering};
	static NEXT: AtomicU64 = AtomicU64::new(1);
	NEXT.fetch_add(1, Ordering::Relaxed)
}

fn take_inflight(name: &str, pred: impl Fn(&Inflight) -> bool) -> Option<Inflight> {
	let mut map = hub().inflight.lock();
	match map.get(name) {
		Some(job) if pred(job) => map.remove(name),
		_ => None,
	}
}

fn deliver(job: Inflight, result: Result<String, String>) {
	for waiter in job.waiters {
		let _ = waiter.send(result.clone());
	}
}

/// How long one wallet build may hold the name before a new request may start.
const INFLIGHT_LIMIT: Duration = Duration::from_secs(180);

fn fail_inflight_later(name: String, id: u64) {
	tokio::spawn(async move {
		tokio::time::sleep(INFLIGHT_LIMIT).await;
		if let Some(job) = take_inflight(&name, |job| job.id == id) {
			deliver(job, Err("the Riptide wallet did not answer in time".into()));
		}
	});
}

/// Drop a handed-out coin invoice once it has been settled, so the next
/// payment of the same amount gets a new one.
pub(crate) fn forget_settled_coin_invoice(hash: PaymentHash) {
	hub().ready.lock().retain(|_, coin| coin.payment_hash != Some(hash));
}

pub fn valid_name(name: &str) -> bool {
	let ok = (1..=32).contains(&name.len())
		&& name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
	ok && !matches!(name, "admin" | "api" | "www" | "root" | "support" | "lnurlp" | "wellknown")
}

fn address_for(name: &str) -> String {
	format!("{name}@{ADDRESS_HOST}")
}

impl Server {
	pub(crate) async fn claim_lightning_address(
		&self, name: &str, user: PublicKey, signature: &[u8],
	) -> anyhow::Result<String> {
		if !valid_name(name) {
			return badarg!("name must be 1-32 letters, digits, or underscores");
		}
		crate::ln::tab::verify_tab_signature(&user, signature, "name", name.as_bytes())?;
		let claimed = self.db.write(async |t| t.claim_lightning_address(name, &user).await).await?;
		match claimed {
			Ok(()) => Ok(address_for(name)),
			Err(reason) => badarg!("{reason}"),
		}
	}

	pub(crate) async fn lightning_address_of(&self, user: PublicKey, signature: &[u8]) -> anyhow::Result<String> {
		crate::ln::tab::verify_tab_signature(&user, signature, "balance", &[])?;
		let name = self.db.read(async |t| t.lightning_address_for_user(&user).await).await?;
		Ok(name.map(|name| address_for(&name)).unwrap_or_default())
	}

	pub(crate) async fn wait_lightning_address_coin(
		&self, user: PublicKey, signature: &[u8],
	) -> anyhow::Result<u64> {
		crate::ln::tab::verify_tab_signature(&user, signature, "balance", &[])?;
		let name = self.db.read(async |t| t.lightning_address_for_user(&user).await).await?
			.context("this key has no lightning address")?;
		let (tx, rx) = oneshot::channel();
		// This runs only while the wallet is idle. If a build was asked for
		// and never came back, hand that same amount over again.
		let resumed = {
			let mut inflight = hub().inflight.lock();
			inflight.get_mut(&name).map(|job| {
				job.id = next_inflight_id();
				(job.amount_sat, job.id)
			})
		};
		if let Some((amount, id)) = resumed {
			let _ = tx.send(amount);
			fail_inflight_later(name, id);
		} else {
			hub().wallet.lock().insert(name, tx);
		}
		match tokio::time::timeout(Duration::from_secs(55), rx).await {
			Ok(Ok(amount)) => Ok(amount),
			_ => Ok(0),
		}
	}

	pub(crate) async fn submit_lightning_address_invoice(
		&self, user: PublicKey, signature: &[u8], bolt11: &str,
	) -> anyhow::Result<()> {
		crate::ln::tab::verify_tab_signature(&user, signature, "name-invoice", bolt11.as_bytes())?;
		let name = self.db.read(async |t| t.lightning_address_for_user(&user).await).await?
			.context("this key has no lightning address")?;
		let parsed = bolt11.parse::<lightning_invoice::Bolt11Invoice>().ok();
		let amount_sat = parsed.as_ref()
			.and_then(|invoice| invoice.amount_milli_satoshis())
			.map(|msat| msat / 1000)
			.or_else(|| hub().inflight.lock().get(&name).map(|job| job.amount_sat))
			.unwrap_or(0);
		let expires_at = parsed.as_ref().and_then(|invoice| {
			invoice.expires_at().map(|until| std::time::SystemTime::UNIX_EPOCH + until)
		}).unwrap_or_else(|| std::time::SystemTime::now() + Duration::from_secs(3600));
		let payment_hash = parsed.as_ref().map(|invoice| {
			PaymentHash::from(*invoice.payment_hash())
		});
		if amount_sat > 0 {
			hub().ready.lock().insert(name.clone(), ReadyCoin {
				amount_sat,
				bolt11: bolt11.to_string(),
				expires_at,
				payment_hash,
			});
		}
		if let Some(job) = take_inflight(&name, |job| job.amount_sat == amount_sat) {
			deliver(job, Ok(bolt11.to_string()));
		}
		Ok(())
	}
}

pub async fn serve(srv: Arc<Server>) -> anyhow::Result<()> {
	let listener = TcpListener::bind(HTTP_ADDR).await.context("lightning address http")?;
	info!("Lightning address pages on {HTTP_ADDR}");
	loop {
		tokio::select! {
			_ = srv.rtmgr.shutdown_signal() => break,
			accepted = listener.accept() => {
				let Ok((sock, _)) = accepted else { continue };
				let srv = srv.clone();
				tokio::spawn(async move {
					if let Err(err) = handle(srv, sock).await {
						warn!("lightning address http: {err:#}");
					}
				});
			}
		}
	}
	Ok(())
}

async fn handle(srv: Arc<Server>, mut sock: tokio::net::TcpStream) -> anyhow::Result<()> {
	let mut buf = vec![0u8; 4096];
	let n = sock.read(&mut buf).await?;
	let req = String::from_utf8_lossy(&buf[..n]);
	let path = req.split_whitespace().nth(1).unwrap_or("/");
	let (path, query) = path.split_once('?').unwrap_or((path, ""));
	let body = route(&srv, path, query).await;
	let resp = format!(
		"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\naccess-control-allow-origin: *\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
		body.len(), body,
	);
	let _ = sock.write_all(resp.as_bytes()).await;
	Ok(())
}

async fn route(srv: &Server, path: &str, query: &str) -> String {
	// Caddy's path handle strips the public prefix, so /name and /name/invoice
	// arrive here as well as the full /.well-known and /lnurlp paths.
	let path = path.trim_end_matches('/');
	let invoice_req = path.ends_with("/invoice");
	let name = path
		.trim_start_matches("/.well-known/lnurlp/")
		.trim_start_matches("/lnurlp/")
		.trim_start_matches('/')
		.trim_end_matches("/invoice");
	if name.is_empty() || name.contains('/') || !valid_name(name) {
		return r#"{"status":"ERROR","reason":"not found"}"#.to_string();
	}
	if invoice_req {
		invoice(srv, name, query).await
	} else {
		metadata(srv, name).await
	}
}

async fn metadata(srv: &Server, name: &str) -> String {
	match srv.db.read(async |t| t.lightning_address_owner(name).await).await {
		Ok(Some(_)) => format!(
			r#"{{"tag":"payRequest","callback":"https://{host}/lnurlp/{name}/invoice","minSendable":1000,"maxSendable":{max},"metadata":"[[\"text/plain\",\"Pay {name} at Riptide Ark\"]]"}}"#,
			host = ADDRESS_HOST,
			max = MAX_SENDABLE_SAT * 1000,
		),
		_ => r#"{"status":"ERROR","reason":"unknown lightning address"}"#.to_string(),
	}
}

async fn invoice(srv: &Server, name: &str, query: &str) -> String {
	let Some(amount_msat) = query.split('&').find_map(|part| {
		part.strip_prefix("amount=").and_then(|v| v.parse::<u64>().ok())
	}) else {
		return r#"{"status":"ERROR","reason":"amount is required"}"#.to_string();
	};
	if amount_msat == 0 || amount_msat % 1000 != 0 {
		return r#"{"status":"ERROR","reason":"amount must be a whole number of sats"}"#.to_string();
	}
	let amount_sat = amount_msat / 1000;
	if amount_sat > MAX_SENDABLE_SAT {
		return r#"{"status":"ERROR","reason":"amount is larger than this node can receive"}"#.to_string();
	}
	let owner = match srv.db.read(async |t| t.lightning_address_owner(name).await).await {
		Ok(Some(owner)) => owner,
		_ => return r#"{"status":"ERROR","reason":"unknown lightning address"}"#.to_string(),
	};
	let user = match PublicKey::from_str(&owner) {
		Ok(user) => user,
		Err(_) => return r#"{"status":"ERROR","reason":"invalid address owner"}"#.to_string(),
	};
	if amount_sat < LIGHTNING_TAB_CHUNK_SAT {
		if srv.lightning_tab_is_opted_out(user).await.unwrap_or(true) {
			return r#"{"status":"ERROR","reason":"this address is not accepting small payments"}"#.to_string();
		}
		match create_tab_invoice(srv, name, &user, Amount::from_sat(amount_sat)).await {
			Ok(bolt11) => format!(r#"{{"pr":"{bolt11}","routes":[]}}"#),
			Err(err) => {
				warn!("lightning address invoice: {err:#}");
				r#"{"status":"ERROR","reason":"could not create the invoice"}"#.to_string()
			},
		}
	} else {
		match ask_wallet(name, amount_sat).await {
			Ok(bolt11) => format!(r#"{{"pr":"{bolt11}","routes":[]}}"#),
			Err(reason) => format!(r#"{{"status":"ERROR","reason":"{reason}"}}"#),
		}
	}
}

async fn create_tab_invoice(
	srv: &Server, name: &str, user: &PublicKey, amount: Amount,
) -> anyhow::Result<String> {
	let preimage = Preimage::random();
	let hash = preimage.compute_payment_hash();
	let invoice = srv.lightning_manager.generate_invoice(
		hash, amount, srv.config.htlc_expiry_delta, Some(format!("Riptide {name}")), None,
	).await?;
	let bytes = preimage.to_vec();
	srv.db.write(async |t| {
		t.store_lightning_address_invoice(&hash, name, &user.to_string(), amount.to_sat() as i64, Some(bytes.as_slice())).await?;
		t.register_lightning_tab_receive(hash, user, amount.to_sat() as i64).await?;
		Ok(())
	}).await?;
	Ok(invoice.to_string())
}

async fn ask_wallet(name: &str, amount_sat: u64) -> Result<String, String> {
	if let Some(bolt11) = ready_invoice(name, amount_sat) {
		return Ok(bolt11);
	}
	let (tx, rx) = oneshot::channel();
	let started = {
		let mut inflight = hub().inflight.lock();
		if let Some(job) = inflight.get_mut(name) {
			if job.amount_sat != amount_sat {
				return Err("a different amount is already being prepared".into());
			}
			job.waiters.push(tx);
			None
		} else {
			let id = next_inflight_id();
			inflight.insert(name.to_string(), Inflight {
				id,
				amount_sat,
				waiters: vec![tx],
			});
			Some(id)
		}
	};
	if let Some(id) = started {
		let sent = hub().wallet.lock().remove(name)
			.map(|waiter| waiter.send(amount_sat).is_ok())
			.unwrap_or(false);
		if sent {
			fail_inflight_later(name.to_string(), id);
		} else if let Some(job) = take_inflight(name, |job| job.id == id) {
			deliver(job, Err(
				"open the Riptide wallet to receive 1000 sats or more".into(),
			));
		}
	}
	match tokio::time::timeout(Duration::from_secs(60), rx).await {
		Ok(Ok(result)) => result,
		_ => Err("the Riptide wallet did not answer in time".into()),
	}
}

/// The hold invoice for a server-created tab payment was accepted. Reveal the
/// preimage the server kept and credit the tab.
pub(crate) async fn settle_held_tab(
	db: &crate::database::Db,
	hold: &mut cln_rpc::plugins::hold::hold_client::HoldClient<tonic::transport::Channel>,
	hash: PaymentHash,
	subscription_id: i64,
) -> anyhow::Result<()> {
	let Some(raw) = db.read(async |t| t.lightning_address_preimage(&hash).await).await? else {
		return Ok(());
	};
	let preimage = Preimage::try_from(raw.as_slice()).context("stored preimage")?;
	if preimage.compute_payment_hash() != hash {
		anyhow::bail!("stored preimage does not match the invoice");
	}
	let _ = hold.settle(cln_rpc::plugins::hold::SettleRequest {
		payment_preimage: preimage.to_vec(),
	}).await;
	db.write(async |t| {
		let _ = t.credit_lightning_tab_receive(hash).await?;
		t.store_lightning_htlc_subscription_status(
			subscription_id,
			crate::database::ln::LightningHtlcSubscriptionStatus::Settled,
			None,
			None,
		).await?;
		Ok(())
	}).await?;
	Ok(())
}
