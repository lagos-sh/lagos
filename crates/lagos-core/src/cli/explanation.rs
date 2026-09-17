use super::Listener;
use crate::routes::RouteTable;

pub(super) fn candidates(
    selected: &RouteTable,
    other: &RouteTable,
    host: Option<&str>,
    path: &str,
    method: &str,
    listener: Listener,
    denied: bool,
) {
    println!("\nPrefix candidates\n");
    let mut count = 0;
    for (table, wrong_listener) in [(selected, false), (other, true)] {
        for candidate in table.prefix_candidates(host, path, method) {
            count += 1;
            let route = candidate.route;
            let mut reasons = Vec::new();
            if wrong_listener {
                let belongs_to = match listener {
                    Listener::Public => "internal",
                    Listener::Internal => "public",
                };
                reasons.push(format!("belongs to {belongs_to} listener"));
            } else if denied {
                reasons.push("blocked by deny-list before route matching".to_string());
            }
            if !candidate.host_matches {
                reasons.push(format!(
                    "{}; requires {}",
                    if host.is_none() {
                        "Host header missing"
                    } else {
                        "host mismatch"
                    },
                    route.host.join(", "),
                ));
            }
            if !candidate.method_matches {
                reasons.push(format!(
                    "method mismatch; allows {}",
                    route.methods.join(", ")
                ));
            }
            println!(
                "  {}  /{}  (group: {}): {}",
                route.id,
                route.prefix,
                route.auth.group(),
                reasons.join("; ")
            );
        }
    }
    if count == 0 {
        println!("  no enabled route has a matching canonical prefix on either listener");
    }
}
