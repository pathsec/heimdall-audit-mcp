# heimdall-audit-mcp

A Claude Code MCP server that decompiles unverified EVM smart contracts using **Heimdall-rs** and runs a comprehensive security audit on the output.

No source code required, point it at a contract address.

---

## Architecture

```
Claude Code
    │  (MCP stdio transport)
    ▼
heimdall-mcp server
    ├── decompile_contract        → shells out to `heimdall decompile`
    ├── analyze_contract_security → Anthropic API (claude-sonnet-4)
    ├── full_audit                → decompile → analyze in one call
    └── check_heimdall            → verify heimdall is installed
```

---

## Prerequisites

### 1. Heimdall-rs

Heimdall uses **bifrost** as its installer:

```bash
curl -L https://raw.githubusercontent.com/Jon-Becker/heimdall-rs/main/bifrost/install | bash
```

Then install heimdall via bifrost:

```bash
bifrost              # installs latest stable (compiles from source)
bifrost --binary     # faster — uses prebuilt binary, skips Rust compilation
```

Verify:

```bash
heimdall --version
```

> If you don't have Rust/cargo, use `bifrost --binary`. Compiling from source can take several minutes.

### 2. Node.js ≥ 18

```bash
node --version
```

### 3. Anthropic API Key

Get one at [console.anthropic.com](https://console.anthropic.com) → API Keys.

### 4. An RPC endpoint (for on-chain contracts)

| Network | Example URL |
|---|---|
| Ethereum Mainnet | `https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY` |
| Sepolia | `https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY` |
| Local fork | `http://localhost:8545` |

For Alchemy, make sure the target network is **enabled** in your app's dashboard under Networks.

---

## Installation & Build

```bash
cd heimdall-mcp
npm install
npm run build
```

---

## Connect to Claude Code

Register the server.

```bash
claude mcp add heimdall-audit \
  --env ANTHROPIC_API_KEY=sk-ant-... \
  -- node /absolute/path/to/heimdall-mcp/dist/index.js
```

Verify it registered:

```bash
claude mcp list
```

---

## Usage in Claude Code

Once connected, just ask Claude something like the following:

```
Audit the contract at 0xdAC17F958D2ee523a2206206994597C13D831ec7
on mainnet. RPC: https://eth-mainnet.g.alchemy.com/v2/KEY
```

```
Decompile 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 using
https://eth-mainnet.g.alchemy.com/v2/KEY and check for reentrancy
```

```
Audit this bytecode: 0x608060405234801561001057600080fd5b50...
```

---

## Tools Reference

### `check_heimdall`
Verifies heimdall is installed and shows version. Run this first if decompilation fails.

### `decompile_contract`
| Param | Type | Required | Description |
|---|---|---|---|
| `target` | string | ✅ | Contract address `0x...` or raw bytecode hex |
| `rpc_url` | string | ⚠️ address only | JSON-RPC endpoint |
| `timeout_seconds` | number | ❌ | Default 120s |

Returns reconstructed pseudo-Solidity + recovered ABI.

### `analyze_contract_security`
| Param | Type | Required | Description |
|---|---|---|---|
| `code` | string | ✅ | Solidity or decompiled pseudo-Solidity |
| `contract_address` | string | ❌ | For report context |
| `rpc_url` | string | ❌ | For report context |
| `extra_context` | string | ❌ | Protocol name, intended behaviour, known issues |

Returns a Markdown security report with severity-ranked findings.

### `full_audit`
| Param | Type | Required | Description |
|---|---|---|---|
| `target` | string | ✅ | Contract address or bytecode |
| `rpc_url` | string | ⚠️ address only | JSON-RPC endpoint |
| `extra_context` | string | ❌ | Additional context for the auditor |
| `timeout_seconds` | number | ❌ | Default 120s |

Chains decompile → analyze in one step.

---

## Vulnerability Classes Covered

| Class | Examples |
|---|---|
| Reentrancy | Single, cross-function, cross-contract, ERC777 hooks |
| Access Control | Missing modifiers, tx.origin auth, unprotected initializers |
| Arithmetic | Overflow/underflow, precision loss, rounding |
| Flash Loans | Oracle manipulation, single-block TWAP, AMM spot prices |
| Proxy/Upgrades | Storage collisions, uninitialized impls, selector clashing |
| External Calls | Unchecked returns, delegatecall to arbitrary addresses |
| DoS | Gas limit loops, forced ETH, griefing |
| Front-running | Sandwich attacks, ordering dependence, slippage |
| Signatures | Replay, malleability, domain separator |
| Token Standards | ERC20 approval race, fee-on-transfer, ERC777 callbacks |
| Time/Block | Timestamp manipulation, blockhash randomness |
| Centralization | Single EOA power, missing timelocks, emergency drain |
| DeFi Patterns | Vault inflation, liquidation mechanics, interest accounting |

---

## Caveats

- **Decompiled code is approximate.** Heimdall reconstructs intent from bytecode — variable names, control flow, and types may be imprecise. The auditor accounts for this and marks uncertain findings as "Suspected".
- **First-pass tool only.** Use alongside verified source analysis (Etherscan, Sourcify) where available.
- **LLMs can miss things.** Do not use as the sole security review for high-value contracts.

---

## Development

```bash
npm run dev    # watch mode
npm run build  # production build
```
