#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub key_path: Option<String>,
    pub entry_node: String,
    pub hop_count: usize,
    pub cashu_mint_url: String,
}
impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            key_path: None,
            entry_node: "[::1]:9001".to_string(),
            hop_count: 3,
            cashu_mint_url: "http://mint.zksn.internal:3338".to_string(),
        }
    }
}
