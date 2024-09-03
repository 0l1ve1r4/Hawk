# Hawk Network Sniffer

Hawk is a basic Rust-based network sniffer supporting:

- Ethernet II
- IPv4
- IPv6
- TCP
- UDP

## Warnings

- This is a simple project, for professional use, I recommend looking for other tools. 

- Only run this code in a network you personally own and control.

---

# Usage

## Build/Run Usage

### Basic

To run the sniffer:

```bash
sudo env "PATH=$HOME/.cargo/bin:$PATH" cargo run
```

> **Warning:** Running as root is required for Layer 2 socket access.

### Without Root

You can avoid running as root by using:

```bash
chmod +x ./build.sh
./build.sh
```

## Application GUI Usage

**Click "Run" to start packet capture**