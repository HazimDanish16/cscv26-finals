# REV04 (rev, 500pts)

id: `rev04`

instancer: False

## Description

[REV04.zip](https://files.59.153.245.189.sslip.io/REV04-ad2981accc5a852c389400eb/REV04.zip)  
SHA-256: `c28c476d1dae0dab9d20a65d4fcb5a1860c930ae1c3d93751afc3107cf46ebbe`

A legitimate monitoring loader installs several eBPF programs. Soon after, the content of some SSH sessions appears in DNS traffic. Not every command is logged — only those matching a specific criteria set.

Determine the command-selection rule, recover the exfiltrated data, and prove the full operation chain.
