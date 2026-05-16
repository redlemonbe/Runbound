pub mod parser;

pub use parser::UnboundConfig;

pub fn load(path: &str) -> anyhow::Result<UnboundConfig> {
    parser::parse_file(path)
}
