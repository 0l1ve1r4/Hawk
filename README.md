> Warnings:
> 
>  - This project is in its early stages, be careful.
>
>  - Only run this code in a network you personally own and control.  

# Hawk Network Sniffer

This is a rudimentary Rust Network Sniffer with these protocols:

- Ethernet II 
- IPv4 
- TCP
- UDP

## Usage

Basic usage:

```bash
sudo env "PATH=$HOME/.cargo/bin:$PATH" cargo run
```
> It must be run as root (because of [Layer 2](https://en.wikipedia.org/wiki/OSI_model) socket access) and only works on unix-like systems.

**Click run to start packet capture, when stopped, click "analysis" to check the captured packets.**