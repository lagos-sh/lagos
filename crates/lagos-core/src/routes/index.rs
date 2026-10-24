//! Arena-backed segment trie. Request work follows configured path segments;
//! it never repeatedly hashes every ancestor of an attacker-controlled path.

use std::collections::HashMap;

use super::RouteConfig;

#[derive(Debug, Default)]
struct Node {
    children: HashMap<String, usize>,
    /// Global route-order positions, preserving host precedence and stable ties.
    routes: Vec<usize>,
}

#[derive(Debug)]
pub(super) struct PrefixIndex {
    nodes: Vec<Node>,
}

impl PrefixIndex {
    pub(super) fn build(routes: &[RouteConfig]) -> Option<Self> {
        // Measured small tables favor the contiguous linear scan. Index the
        // larger tables whose scan cost grows with route count.
        if routes.len() <= 32 {
            return None;
        }
        let mut nodes = vec![Node::default()];
        for (position, route) in routes.iter().enumerate() {
            let mut current = 0;
            if !route.prefix.is_empty() {
                for segment in route.prefix.split('/') {
                    let child = nodes
                        .get(current)
                        .and_then(|n| n.children.get(segment))
                        .copied();
                    current = match child {
                        Some(child) => child,
                        None => {
                            let child = nodes.len();
                            nodes.push(Node::default());
                            if let Some(parent) = nodes.get_mut(current) {
                                parent.children.insert(segment.to_string(), child);
                            }
                            child
                        }
                    };
                }
            }
            if let Some(node) = nodes.get_mut(current) {
                node.routes.push(position);
            }
        }
        Some(Self { nodes })
    }

    pub(super) fn find<'a>(
        &self,
        routes: &'a [RouteConfig],
        path: &str,
        method: &str,
        host: Option<&str>,
    ) -> Option<&'a RouteConfig> {
        let mut best = None;
        let mut current = 0;
        if path.is_empty() {
            self.consider(current, routes, method, host, &mut best);
        } else {
            // Empty prefixes match only the empty normalized path. Do not
            // accidentally turn an invalid root rule into a catch-all.
            for segment in path.split('/') {
                let Some(child) = self
                    .nodes
                    .get(current)
                    .and_then(|node| node.children.get(segment))
                else {
                    break;
                };
                current = *child;
                self.consider(current, routes, method, host, &mut best);
            }
        }
        best.and_then(|position| routes.get(position))
    }

    fn consider(
        &self,
        node: usize,
        routes: &[RouteConfig],
        method: &str,
        host: Option<&str>,
        best: &mut Option<usize>,
    ) {
        let Some(node) = self.nodes.get(node) else {
            return;
        };
        for &position in &node.routes {
            if best.is_some_and(|best| position >= best) {
                break;
            }
            if routes
                .get(position)
                .is_some_and(|route| route.matches_method(method) && route.matches_host(host))
            {
                *best = Some(position);
                break;
            }
        }
    }
}
