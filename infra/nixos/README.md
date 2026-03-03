# ZKSN NixOS Node

RAM-only mix node configuration. Hardware seizure yields zero data.

## Properties

| Feature | Value |
|---|---|
| Root filesystem | tmpfs — all writes lost on reboot |
| Boot verification | dm-verity (config pending image builder) |
| Key storage | LUKS2 encrypted USB only |
| Network | Yggdrasil (200::/7) + firewall drop everything else |
| Anonymous services | i2pd (HTTP 4444, SOCKS 4447) |
| Logging | Volatile (journald in RAM only) |

## Deploy

```bash
nixos-rebuild switch --target-host root@[200:your:node::1] --flake .#zksn-node
```
