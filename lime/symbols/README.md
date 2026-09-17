# Prepared Linux symbols

`linux/Ubuntu_6.8.0-124-generic_22.04.1.json.xz` is a pre-generated ISF for
Ubuntu kernel package `6.8.0-124.124~22.04.1`, amd64. Its complete linux_banner
matches the banner at file offset `0xbe74411f` in `/mnt/d/tryhard/evidence.mem`.
The memory dump and ISF banner have not been patched.

Source: https://github.com/Abyss-W4tcher/volatility3-symbols/tree/master/Ubuntu/amd64/6.8.0/124/generic

Original filename: `Ubuntu_6.8.0-124-generic_6.8.0-124.124~22.04.1_amd64.json.xz`

Downloaded size: 2,880,588 bytes.
Local SHA-256: `00006dca6423ad72288074aa091d3ab927d8e51e7371367f8037620d99c5b117`
(recorded locally for reproducibility; not an upstream signature).

Run in WSL:

```bash
vol -q -s /mnt/d/tools/lime/symbols -f /mnt/d/tryhard/evidence.mem linux.pslist.PsList
```

Keep this directory for future use. No dwarf2json build is needed for this dump.
Other dumps still require their own exact matching symbols.

Verified locally with Volatility 3 2.28.0: `linux.pslist.PsList` completed with exit
status 0 and returned process records including systemd (PID 1), bash (PID 3334),
and avml (PID 3696). Other plugins have not yet been tested.
