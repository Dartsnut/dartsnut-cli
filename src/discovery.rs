use anyhow::{Context, Result};
use if_addrs::get_if_addrs;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpStream, lookup_host};
use tokio::task::JoinSet;
use tokio::time::timeout;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanTarget {
    pub address: Ipv4Addr,
    pub hostname: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenTarget {
    pub address: Ipv4Addr,
    pub hostname: Option<String>,
}

impl ScanTarget {
    pub fn label(&self) -> String {
        self.hostname
            .as_ref()
            .map(|host| format!("{} ({host})", self.address))
            .unwrap_or_else(|| self.address.to_string())
    }
}

pub async fn build_scan_targets(ip: Option<&str>) -> Result<Vec<ScanTarget>> {
    let mut by_address = HashMap::<Ipv4Addr, Option<String>>::new();
    if let Some(value) = ip {
        let value = value.trim();
        if let Ok(address) = value.parse::<Ipv4Addr>() {
            by_address.insert(address, None);
        } else {
            let resolved = lookup_host((value, 22))
                .await
                .with_context(|| format!("resolve target {value}"))?;
            for socket in resolved {
                if let IpAddr::V4(address) = socket.ip() {
                    by_address
                        .entry(address)
                        .or_insert_with(|| Some(value.to_owned()));
                }
            }
            if by_address.is_empty() {
                anyhow::bail!("target {value} has no IPv4 address");
            }
        }
    } else {
        for interface in get_if_addrs().context("enumerate network interfaces")? {
            if let if_addrs::IfAddr::V4(address) = interface.addr {
                if address.ip.is_loopback() {
                    continue;
                }
                add_subnet_candidates(&mut by_address, address.ip);
            }
        }
        for hostname in ["dartsnut.local", "raspberrypi.local"] {
            if let Ok(resolved) = lookup_host((hostname, 22)).await {
                for socket in resolved {
                    if let IpAddr::V4(address) = socket.ip() {
                        by_address
                            .entry(address)
                            .and_modify(|existing| {
                                if existing.is_none() {
                                    *existing = Some(hostname.to_owned());
                                }
                            })
                            .or_insert_with(|| Some(hostname.to_owned()));
                    }
                }
            }
        }
    }

    let mut targets = by_address
        .into_iter()
        .map(|(address, hostname)| ScanTarget { address, hostname })
        .collect::<Vec<_>>();
    if ip.is_none() {
        targets.sort_by_key(|target| u32::from(target.address));
    }
    Ok(targets)
}

fn add_subnet_candidates(by_address: &mut HashMap<Ipv4Addr, Option<String>>, interface: Ipv4Addr) {
    let octets = interface.octets();
    for last in 1..=254 {
        let candidate = Ipv4Addr::new(octets[0], octets[1], octets[2], last);
        if candidate != interface && !candidate.is_loopback() {
            by_address.entry(candidate).or_insert(None);
        }
    }
}

pub async fn scan_port22(targets: Vec<ScanTarget>) -> Vec<OpenTarget> {
    scan_port22_progress(targets, |_, _, _, _| {}).await
}

pub async fn scan_port22_progress(
    targets: Vec<ScanTarget>,
    progress: impl FnMut(usize, usize, &ScanTarget, usize),
) -> Vec<OpenTarget> {
    scan_port(targets, 22, progress).await
}

async fn scan_port(
    targets: Vec<ScanTarget>,
    port: u16,
    mut progress: impl FnMut(usize, usize, &ScanTarget, usize),
) -> Vec<OpenTarget> {
    let total = targets.len();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(64));
    let mut tasks = JoinSet::new();
    for target in targets {
        let semaphore = semaphore.clone();
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok();
            let address = SocketAddr::new(IpAddr::V4(target.address), port);
            let open = timeout(Duration::from_secs(1), TcpStream::connect(address))
                .await
                .is_ok_and(|result| result.is_ok());
            (target, open)
        });
    }

    let mut completed = 0;
    let mut open = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok((target, is_open)) = result {
            completed += 1;
            if is_open {
                open.push(OpenTarget {
                    address: target.address,
                    hostname: target.hostname.clone(),
                });
            }
            progress(completed, total, &target, open.len());
        }
    }
    open.sort_by_key(|target| u32::from(target.address));
    open
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn deduplicates_overlapping_24s_and_omits_self_and_broadcast() {
        let mut candidates = HashMap::new();
        add_subnet_candidates(&mut candidates, Ipv4Addr::new(192, 168, 4, 10));
        add_subnet_candidates(&mut candidates, Ipv4Addr::new(192, 168, 4, 11));
        assert_eq!(candidates.len(), 254);
        assert!(!candidates.contains_key(&Ipv4Addr::new(192, 168, 4, 0)));
        assert!(!candidates.contains_key(&Ipv4Addr::new(192, 168, 4, 255)));
    }

    #[tokio::test]
    async fn detects_open_and_closed_local_port() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = ScanTarget {
            address: Ipv4Addr::LOCALHOST,
            hostname: None,
        };
        let mut updates = Vec::new();
        let open = scan_port(vec![target.clone()], port, |done, total, _, count| {
            updates.push((done, total, count));
        })
        .await;
        assert_eq!(open.len(), 1);
        assert_eq!(updates, [(1, 1, 1)]);
        drop(listener);
        let closed = scan_port(vec![target], port, |_, _, _, _| {}).await;
        assert!(closed.is_empty());
    }
}
