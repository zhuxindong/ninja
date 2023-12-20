use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Instant,
};

use futures::future::join_all;
use tokio::sync::OnceCell;
use trust_dns_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

pub(super) const FASTEST_DNS_CONFIG: OnceCell<ResolverConfig> = OnceCell::const_new();

/// IP addresses for Tencent Public DNS
pub const TENCENT_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(119, 29, 29, 29)),
    IpAddr::V4(Ipv4Addr::new(119, 29, 29, 30)),
    IpAddr::V6(Ipv6Addr::new(0x2402, 0x4e00, 0, 0, 0, 0, 0, 0x1)),
];

/// IP addresses for Aliyun Public DNS
pub const ALIYUN_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
    IpAddr::V4(Ipv4Addr::new(223, 6, 6, 6)),
    IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0, 0, 0, 0, 0, 0x1)),
];

pub trait ResolverConfigExt {
    fn tencent() -> ResolverConfig;
    fn aliyun() -> ResolverConfig;
}

impl ResolverConfigExt for ResolverConfig {
    fn tencent() -> ResolverConfig {
        ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(TENCENT_IPS, 53, true),
        )
    }

    fn aliyun() -> ResolverConfig {
        ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(ALIYUN_IPS, 53, true),
        )
    }
}

/// Fastest DNS resolver
pub async fn load_fastest_dns(enabled: bool) -> anyhow::Result<()> {
    if !enabled {
        return Ok(());
    }

    let mut tasks = Vec::new();

    let mut opts = ResolverOpts::default();
    opts.ip_strategy = trust_dns_resolver::config::LookupIpStrategy::Ipv4AndIpv6;

    let configs = vec![
        ResolverConfig::google(),
        ResolverConfig::quad9(),
        ResolverConfig::cloudflare(),
        ResolverConfig::tencent(),
        ResolverConfig::aliyun(),
    ];

    for config in configs {
        let resolver = TokioAsyncResolver::tokio(config.clone(), opts.clone());
        let task = async move {
            let start = Instant::now();
            let ips = resolver.lookup_ip("chat.openai.com").await?;
            let _ = ips.iter().collect::<Vec<_>>();
            let elapsed = start.elapsed();
            Ok((elapsed, config))
        };
        tasks.push(task);
    }

    // Join all tasks and return the fastest DNS
    let r = join_all(tasks)
        .await
        .into_iter()
        .collect::<anyhow::Result<Vec<_>>>()?;

    let (elapsed, conf) = r
        .into_iter()
        .min_by_key(|(elapsed, _)| *elapsed)
        .ok_or_else(|| anyhow::anyhow!("No fastest dns"))?;

    // '\n*' split fastest_dns_group
    let fastest_dns_group = conf
        .name_servers()
        .iter()
        .map(|ns| ns.socket_addr.to_string())
        .collect::<Vec<_>>()
        .join("\n* ");

    tracing::info!("Fastest DNS group ({elapsed:?}):\n* {fastest_dns_group}");

    // Set fastest dns group
    FASTEST_DNS_CONFIG
        .set(conf)
        .map_err(|_| anyhow::anyhow!("Failed to set fastest dns group"))?;
    Ok(())
}
