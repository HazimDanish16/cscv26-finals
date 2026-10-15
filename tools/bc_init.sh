#!/usr/bin/env bash
# Usage (WSL): tools/bc_init.sh <challenge-dir>
# Scaffolds a Foundry project for a blockchain challenge: forge init + an Exploit.t.sol
# skeleton ready to fill in. Run forge test from inside <challenge-dir> once written.
set -e
export PATH="$PATH:$HOME/.foundry/bin"
dir="$1"
[ -z "$dir" ] && { echo "usage: $0 <challenge-dir>"; exit 1; }
command -v forge >/dev/null 2>&1 || { echo "!! forge not found - did tools/setup_wsl.sh's foundry step run?"; exit 1; }

mkdir -p "$dir"
forge init --no-git --force "$dir"
cat > "$dir/test/Exploit.t.sol" <<'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "forge-std/Test.sol";
// import "../src/Target.sol";  // drop the challenge's given contract source into src/ and import it

contract ExploitTest is Test {
    function setUp() public {
        // vm.createSelectFork("<rpc-url>");           // to rehearse against the real deployed state
        // target = Target(<deployed-address>);
    }

    function testExploit() public {
        // write the attack here; `forge test -vvvv` for full traces when debugging
    }
}
EOF
echo "scaffolded at $dir - drop the challenge's contract source into $dir/src/, write the"
echo "attack in $dir/test/Exploit.t.sol, then: cd $dir && forge test -vvvv"
echo "once it passes locally, broadcast for real: forge script ... --broadcast --rpc-url <url> --private-key <key>"
