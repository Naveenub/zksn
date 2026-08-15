//! Python bindings for the ZKSN client SDK.
//!
//! Build: `cd client && maturin develop --features python`
//! Usage:
//!   import asyncio, zksn_client
//!
//!   async def main():
//!       cfg = zksn_client.ClientConfig()
//!       cfg.entry_node = "[200::1]:9001"
//!       cfg.yggdrasil_only = False  # dev/testnet only
//!       client = await zksn_client.ZksnClient.connect(cfg)
//!       print(client.fingerprint())
//!       await client.send("aa" * 32, b"hello")
//!       async for msg in await client.receive():
//!           print(msg)
//!
//!   asyncio.run(main())
//!
//! Every I/O method mirrors `ZksnClient` in `lib.rs` one-to-one (`connect` ==
//! `ZksnClient::new`, plus `fingerprint`, `routing_pubkey_hex`, `peer_count`,
//! `send`, `receive`) and is async — pyo3-async-runtimes bridges the tokio
//! futures onto Python's asyncio event loop.
//!
//! Pinned to pyo3 >=0.29 (RUSTSEC-2025-0020, RUSTSEC-2026-0177). Uses the
//! post-0.24 API: `PyBytes::new` (no `_bound` suffix) and `Bound<'py, T>`
//! wrapper types throughout. NOT independently compiled/tested in this
//! environment (no Python toolchain available in this sandbox) — verify
//! with `cd client && maturin develop --features python` before shipping.

use std::sync::Arc;

use pyo3::exceptions::{PyRuntimeError, PyStopAsyncIteration};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use tokio::sync::{mpsc, Mutex as AsyncMutex};

use crate::{ClientConfig, ZksnClient as RustZksnClient};

fn to_py_err(e: anyhow::Error) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

/// Async iterator over incoming messages, yielded as `bytes`.
/// Obtained from `await client.receive()`; use with `async for`.
#[pyclass(name = "ReceiveStream")]
pub struct PyReceiveStream {
    rx: Arc<AsyncMutex<mpsc::Receiver<Vec<u8>>>>,
}

#[pymethods]
impl PyReceiveStream {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let rx = Arc::clone(&self.rx);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            match rx.lock().await.recv().await {
                Some(msg) => {
                    let py_bytes: Py<PyBytes> =
                        Python::with_gil(|py| PyBytes::new(py, &msg).into());
                    Ok(py_bytes)
                }
                // Channel closed — signals end of async iteration to Python.
                None => Err(PyStopAsyncIteration::new_err(())),
            }
        })
    }
}

/// The ZKSN client. Construct with `await ZksnClient.connect(config)`.
#[pyclass(name = "ZksnClient")]
pub struct PyZksnClient {
    inner: Arc<RustZksnClient>,
}

#[pymethods]
impl PyZksnClient {
    /// Connect and start peer discovery. Async — must be awaited.
    /// Mirrors `ZksnClient::new`.
    #[staticmethod]
    fn connect<'py>(py: Python<'py>, config: ClientConfig) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let client = RustZksnClient::new(config).await.map_err(to_py_err)?;
            Ok(PyZksnClient {
                inner: Arc::new(client),
            })
        })
    }

    /// This node's identity fingerprint.
    fn fingerprint(&self) -> String {
        self.inner.fingerprint()
    }

    /// This node's X25519 routing public key, hex-encoded (64 chars).
    fn routing_pubkey_hex(&self) -> String {
        self.inner.routing_pubkey_hex()
    }

    /// Number of live peers currently known. Async — must be awaited.
    fn peer_count<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(inner.peer_count().await) })
    }

    /// Send `payload` (bytes) to the peer identified by `recipient_pubkey_hex`
    /// (64 hex chars, i.e. that peer's `routing_pubkey_hex()`).
    /// Async — must be awaited.
    fn send<'py>(
        &self,
        py: Python<'py>,
        recipient_pubkey_hex: String,
        payload: Vec<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner
                .send(&recipient_pubkey_hex, &payload)
                .await
                .map_err(to_py_err)
        })
    }

    /// Start listening for incoming messages. Returns a `ReceiveStream`
    /// (async iterator, yields `bytes`). Async — must be awaited.
    fn receive<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let rx = inner.receive().await.map_err(to_py_err)?;
            Ok(PyReceiveStream {
                rx: Arc::new(AsyncMutex::new(rx)),
            })
        })
    }
}

#[pymodule]
fn zksn_client(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ClientConfig>()?;
    m.add_class::<PyZksnClient>()?;
    m.add_class::<PyReceiveStream>()?;
    Ok(())
}
