//! Noise_XX handshake — mutual authentication with forward secrecy.
use snow::{Builder, TransportState};
use thiserror::Error;

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("Encryption failed")]
    EncryptFailed,
    #[error("Decryption failed")]
    DecryptFailed,
}

/// Completed Noise session — can encrypt/decrypt transport messages.
pub struct NoiseSession {
    state: TransportState,
}

impl NoiseSession {
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; plaintext.len() + 16];
        let len = self
            .state
            .write_message(plaintext, &mut buf)
            .map_err(|_| NoiseError::EncryptFailed)?;
        buf.truncate(len);
        Ok(buf)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self
            .state
            .read_message(ciphertext, &mut buf)
            .map_err(|_| NoiseError::DecryptFailed)?;
        buf.truncate(len);
        Ok(buf)
    }
}

/// Initiator side of a Noise_XX handshake.
pub struct NoiseInitiator {
    state: snow::HandshakeState,
}

impl NoiseInitiator {
    pub fn new_with_key(private_key: &[u8]) -> Result<Self, NoiseError> {
        let state = Builder::new(
            NOISE_PARAMS
                .parse()
                .map_err(|e: snow::Error| NoiseError::HandshakeFailed(e.to_string()))?,
        )
        .local_private_key(private_key)
        .build_initiator()
        .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;
        Ok(Self { state })
    }

    /// Step 1: → e
    pub fn write_message1(&mut self) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; 65535];
        let len = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Step 2: ← e, ee, s, es
    pub fn read_message2(&mut self, msg: &[u8]) -> Result<(), NoiseError> {
        let mut buf = vec![0u8; 65535];
        self.state
            .read_message(msg, &mut buf)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;
        Ok(())
    }

    /// Step 3: → s, se  →  complete handshake
    pub fn write_message3(mut self) -> Result<(Vec<u8>, NoiseSession), NoiseError> {
        let mut buf = vec![0u8; 65535];
        let len = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;
        buf.truncate(len);
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;
        Ok((buf, NoiseSession { state: transport }))
    }
}

/// Responder side of a Noise_XX handshake.
pub struct NoiseResponder {
    state: snow::HandshakeState,
}

impl NoiseResponder {
    pub fn new_with_key(private_key: &[u8]) -> Result<Self, NoiseError> {
        let state = Builder::new(
            NOISE_PARAMS
                .parse()
                .map_err(|e: snow::Error| NoiseError::HandshakeFailed(e.to_string()))?,
        )
        .local_private_key(private_key)
        .build_responder()
        .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;
        Ok(Self { state })
    }

    /// Step 1: ← e
    pub fn read_message1(&mut self, msg: &[u8]) -> Result<(), NoiseError> {
        let mut buf = vec![0u8; 65535];
        self.state
            .read_message(msg, &mut buf)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;
        Ok(())
    }

    /// Step 2: → e, ee, s, es
    pub fn write_message2(&mut self) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; 65535];
        let len = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Step 3: ← s, se  →  complete handshake
    pub fn read_message3(mut self, msg: &[u8]) -> Result<NoiseSession, NoiseError> {
        let mut buf = vec![0u8; 65535];
        self.state
            .read_message(msg, &mut buf)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;
        Ok(NoiseSession { state: transport })
    }
}

/// Complete a full Noise_XX handshake between initiator and responder in memory.
/// Returns (initiator_session, responder_session).
pub fn handshake_in_memory(
    initiator_key: &[u8],
    responder_key: &[u8],
) -> Result<(NoiseSession, NoiseSession), NoiseError> {
    let mut i = NoiseInitiator::new_with_key(initiator_key)?;
    let mut r = NoiseResponder::new_with_key(responder_key)?;

    let msg1 = i.write_message1()?;
    r.read_message1(&msg1)?;
    let msg2 = r.write_message2()?;
    i.read_message2(&msg2)?;
    let (msg3, i_session) = i.write_message3()?;
    let r_session = r.read_message3(&msg3)?;

    Ok((i_session, r_session))
}

fn generate_keypair() -> Vec<u8> {
    Builder::new(NOISE_PARAMS.parse().unwrap())
        .generate_keypair()
        .unwrap()
        .private
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_xx_handshake_succeeds() {
        let i_key = generate_keypair();
        let r_key = generate_keypair();
        let result = handshake_in_memory(&i_key, &r_key);
        assert!(result.is_ok(), "Noise_XX handshake must succeed");
    }

    #[test]
    fn test_noise_encrypt_decrypt_roundtrip() {
        let i_key = generate_keypair();
        let r_key = generate_keypair();
        let (mut i_sess, mut r_sess) = handshake_in_memory(&i_key, &r_key).unwrap();

        let plaintext = b"sovereign network message";
        let ct = i_sess.encrypt(plaintext).unwrap();
        let decoded = r_sess.decrypt(&ct).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn test_noise_wrong_direction_fails() {
        let i_key = generate_keypair();
        let r_key = generate_keypair();
        let (mut i_sess, _r_sess) = handshake_in_memory(&i_key, &r_key).unwrap();

        let ct = i_sess.encrypt(b"msg").unwrap();
        // Same session that encrypted cannot also decrypt (send/recv keys are separate)
        assert!(i_sess.decrypt(&ct).is_err());
    }
}
