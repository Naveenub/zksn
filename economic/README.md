# ZKSN Economic Layer

Two-tier anonymous payment system for ZKSN.

## Overview

```
User ──XMR──▶ Cashu Mint ──blind tokens──▶ User
                                              │
                                              ▼
                                    [Sphinx Packet + Token]
                                              │
                                              ▼
                                         Mix Node
                                              │
                                    [batch redeem tokens]
                                              │
                                              ▼
                                         Cashu Mint ──XMR──▶ Mix Node
```

## Cashu (Micropayments)

Cashu tokens are Chaumian blind signatures. The mint cannot link which token it issued to which token was redeemed, even if it logs every transaction.

See `src/cashu.rs` for the token implementation.

## Monero (Settlement)

All inter-node settlement uses Monero (XMR):
- Stealth addresses: one-time addresses per payment
- RingCT: transaction amounts hidden
- Ring signatures: sender hidden among decoys

See `src/monero.rs` for the RPC interface.

## Running a Local Mint (Dev)

```bash
pip install cashu
mint --host 127.0.0.1 --port 3338
```

Or use the Docker compose:

```bash
cd infra/docker
docker compose up cashu-mint
```
