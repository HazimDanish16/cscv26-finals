# Blockchain/Web3 CTF cheat sheet

Standard challenge shape: given a deployed contract (source + ABI, or just bytecode), an RPC
endpoint, and a private key with some funds. Goal is usually to drain a contract, become owner,
or satisfy some win condition that the challenge's checker reads back from chain state.

## Workflow
1. **Get the contract source** (usually given) or decompile bytecode (`cast etherscan-source`
   if verified, or a bytecode decompiler like Dedaub/Heimdall if not - lower priority, most CTFs
   give source).
2. **Read the contract for the vuln** - see classes below.
3. **Write the exploit as a Foundry test first** (`forge test`) against a local fork/fresh EVM -
   fast, free, no risk of breaking the real instance. Use `tools/bc_project/` as a starting
   skeleton (copy it per-challenge).
4. **Once it works locally, point it at the real RPC** and execute for real with `cast send` or a
   `forge script --broadcast --rpc-url <url> --private-key <key>`.
5. Confirm the win condition on-chain (`cast call` to check contract state) before telling the
   user it's solved.

## Common vulnerability classes (check these first)
- **Reentrancy**: external call (`.call{value:}`, `.transfer`, token transfer with a callback like
  ERC777/ERC721) happens *before* state is updated. Classic: balance drained via a `receive()`
  callback that re-calls the vulnerable function before balance hits zero.
- **Integer overflow/underflow**: only a concern if `pragma solidity <0.8.0` (0.8+ reverts by
  default) or inside an `unchecked {}` block.
- **Access control**: missing/wrong `onlyOwner`-style modifier, `tx.origin` used instead of
  `msg.sender` for auth (phishable via a malicious contract the owner interacts with),
  uninitialized owner in a proxy/upgradeable contract.
- **Delegatecall injection**: `delegatecall` to an attacker-controlled or mismatched-storage-
  layout contract - can let you overwrite arbitrary storage slots (e.g. owner).
- **Price/oracle manipulation**: contract reads price from an on-chain AMM pool reserve ratio
  directly - flash-loan a huge swap to skew the ratio, trigger the mispriced logic, repay the loan.
- **Signature replay / missing nonce**: a signed message (meta-tx, permit, etc.) can be replayed
  because it's not bound to a nonce/chainid/contract address.
- **Unchecked low-level call return value**: `.call(...)` without checking the bool return -
  silent failure the caller can exploit.
- **Front-running / commit-reveal missing**: an on-chain secret or order can be seen in the
  mempool and exploited before it executes.
- **Self-destruct funding trick**: sending ETH to a contract via `selfdestruct` from another
  contract bypasses `receive()`/`fallback()` - can break balance-based invariants (`address(this).balance == trackedTotal`).

## Tools
- `forge`/`cast`/`anvil` (Foundry, in PATH via ~/.foundry/bin) - compile, test, deploy, send txs,
  read state, fork a live chain (`anvil --fork-url <rpc>`) to rehearse against real state locally.
- `~/ctfenv/bin/slither <path>` - static analyzer, flags common bug classes automatically; run
  this first on any given source as a free first pass before manual review.
- `~/ctfenv/bin/python` + `web3` (pip, installed) - for scripting interactions beyond what cast's
  one-liners cover (e.g. complex calldata, event log parsing, batch calls).
- `cast call <addr> "<sig>" --rpc-url <url>` / `cast send ... --private-key <key>` - quick reads
  and writes without writing a script.
- `cast sig "transfer(address,uint256)"` / `cast 4byte <selector>` - function selector lookups.

## Useful cast one-liners
```
cast balance <addr> --rpc-url <url>
cast call <contract> "owner()(address)" --rpc-url <url>
cast send <contract> "deposit()" --value 1ether --private-key <key> --rpc-url <url>
cast run <tx-hash> --rpc-url <url>          # replay/debug a transaction
anvil --fork-url <rpc-url>                  # local fork of the live chain to rehearse against
```
