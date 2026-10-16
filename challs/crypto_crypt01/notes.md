# CRYPT01 (crypto, 500pts)

id: `crypto01`

instancer: False

## Description

[ghostwire.pcapng](https://files.59.153.245.189.sslip.io/CRYPTO01-e5a75ee2635e5123db6dffb7/ghostwire.pcapng)  
SHA-256: `63ff08aff1cbc2078012ba245d3a2f8a6f35993bfcdcbbc3eba8d5bc4c55e374`

A single capture off a compromised host. The implant runs its own binary C2 over tcp/42871 - no dissector, no key on the wire. Reassemble the exfil and pull the flag. Everything you need is in the pcap.
