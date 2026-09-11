//! The stock gateway: everything declarative, no extensions compiled in.
//!
//! A deployment that needs custom policy links `lagos-core`, registers its
//! own extensions, and calls the same CLI.

fn main() -> anyhow::Result<()> {
    lagos_core::Cli::run(Vec::new())
}
