//! Reproducible, dependency-free microbenchmarks. Samples are batch means,
//! not HTTP latency distributions. Run with `cargo bench --bench policy`.
#![allow(clippy::expect_used)] // Constant local benchmark fixtures only.

use std::hint::black_box;
use std::time::{Duration, Instant};

use lagos_core::config::{MissingKey, RateLimitConfig, RateLimitKey};
use lagos_core::headers::HeaderPlan;
use lagos_core::ratelimit::{Limiter, admission_key};
use lagos_core::routes::{RouteGroups, RouteTable};

fn measure(name: &str, routes: usize, samples: usize, batch: usize, mut operation: impl FnMut()) {
    for _ in 0..32 {
        operation();
    }
    let mut times = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        for _ in 0..batch {
            operation();
        }
        times.push(start.elapsed().as_secs_f64() * 1e9 / batch as f64);
    }
    times.sort_by(f64::total_cmp);
    let percentile = |percent| {
        times
            .get((samples.saturating_sub(1) * percent) / 100)
            .copied()
            .unwrap_or_default()
    };
    let mean = times.iter().sum::<f64>() / samples as f64;
    println!(
        "{name},{routes},{:.2},{:.2},{:.2},{mean:.2}",
        percentile(50),
        percentile(95),
        percentile(99)
    );
}

fn groups(count: usize) -> RouteGroups {
    let routes: Vec<_> = (0..count)
        .map(|i| {
            serde_json::json!({
                "id": format!("route-{i}"), "prefix": format!("/service/{i}"),
                "upstream": "origin", "methods": ["GET", "POST"],
                "host": if i % 3 == 0 { vec!["api.example.test"] } else { Vec::new() },
            })
        })
        .collect();
    serde_json::from_value(serde_json::json!({"public": routes})).expect("benchmark routes")
}

fn main() {
    println!(
        "workload,routes,p50_batch_ns_per_op,p95_batch_ns_per_op,p99_batch_ns_per_op,mean_ns_per_op"
    );
    for count in [10, 100, 1_000, 10_000] {
        let source = groups(count);
        let table = RouteTable::build(source.clone());
        let paths: Vec<_> = (0..count).map(|i| format!("service/{i}/item")).collect();
        let mut index = 0;
        measure("route_mixed_hit", count, 200, 32, || {
            let path = paths.get(index % count).expect("bounded benchmark index");
            index = index.wrapping_add(71);
            black_box(table.match_request(Some("api.example.test"), black_box(path), "GET"));
        });
        measure("route_miss", count, 200, 32, || {
            black_box(table.match_request(
                Some("other.example.test"),
                black_box("missing/item"),
                "GET",
            ));
        });
        measure("route_build", count, 30, 1, || {
            black_box(RouteTable::build(source.clone()));
        });
    }
    let mut headers = http::HeaderMap::new();
    headers.insert("x-client", http::HeaderValue::from_static("alice"));
    let header_selector = RateLimitKey::Header("x-client".into());
    measure("header_key", 0, 200, 128, || {
        let _ = black_box(admission_key(
            &header_selector,
            MissingKey::Reject,
            0,
            "route",
            None,
            None,
            None,
            &headers,
        ));
    });
    measure("header_plan", 0, 200, 128, || {
        let mut plan = HeaderPlan::new();
        plan.strip("authorization").strip("x-auth-subject");
        plan.set("x-auth-subject", "alice")
            .set("x-request-id", "benchmark-fixture");
        black_box(plan);
    });
    let config: RateLimitConfig =
        serde_yaml_ng::from_str("requests: 18446744073709551615\ninterval: 60s\nkey: route")
            .expect("benchmark limiter");
    let limiter = Limiter::new(&config);
    measure("rate_lookup_warm", 0, 200, 128, || {
        black_box(limiter.check("r|alice"));
    });
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/jwt.json")).expect("public JWT fixture");
    let key = jsonwebtoken::DecodingKey::from_rsa_components(
        fixture.get("n").and_then(|v| v.as_str()).expect("modulus"),
        fixture.get("e").and_then(|v| v.as_str()).expect("exponent"),
    )
    .expect("fixture public key");
    let token = fixture
        .get("token")
        .and_then(|v| v.as_str())
        .expect("fixture JWT");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&["https://benchmark.invalid"]);
    validation.set_audience(&["lagos-benchmark"]);
    measure("jwt_rs256_verify", 0, 200, 32, || {
        black_box(
            jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(
                token,
                &key,
                &validation,
            )
            .expect("valid fixture"),
        );
    });
    let (raw, expanded) = lagos_core::config::GatewayConfig::parse("benchmark.yml",
        "upstreams:\n  single: http://127.0.0.1:8080\n  pool: {targets: ['http://127.0.0.1:8080', 'http://127.0.0.1:8081']}\nroutes: {public: [{prefix: /bench, upstream: single}]}\n").expect("upstream fixture");
    let resolved = raw.resolve(&expanded).expect("valid upstreams");
    let (upstreams, _) =
        lagos_core::upstream::resolve_all(&resolved.upstreams).expect("literal upstream discovery");
    for name in ["single", "pool"] {
        let upstream = upstreams.get(name).expect("configured benchmark upstream");
        measure(&format!("upstream_select_{name}"), 0, 200, 128, || {
            black_box(upstream.select(b"fixture"));
        });
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("benchmark runtime");
    let resolver =
        lagos_core::dns::Resolver::new(Duration::from_secs(60), 1024, Duration::from_secs(1));
    runtime
        .block_on(resolver.resolve("127.0.0.1:8080"))
        .expect("literal DNS fixture");
    measure("dns_literal_warm", 0, 200, 128, || {
        let _ = black_box(runtime.block_on(resolver.resolve("127.0.0.1:8080")));
    });
}
