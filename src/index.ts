#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";

import { checkHeimdall, decompileContract } from "./decompile.js";
import { analyzeContractSecurity } from "./analyze.js";

// ─── Tool Definitions ────────────────────────────────────────────────────────

const TOOLS: Tool[] = [
  {
    name: "decompile_contract",
    description: `Decompile an EVM smart contract using Heimdall-rs.
Accepts either:
  • A 20-byte contract address (0x...) + an RPC URL
  • Raw hex bytecode

Returns reconstructed pseudo-Solidity source code and, when available, the recovered ABI.
This does NOT require the contract to be verified on Etherscan.`,
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description:
            "Contract address (0x + 40 hex chars) or raw bytecode hex string",
        },
        rpc_url: {
          type: "string",
          description:
            "JSON-RPC endpoint to fetch bytecode from (required for address targets). Examples: https://eth-mainnet.g.alchemy.com/v2/KEY, https://mainnet.infura.io/v3/KEY, http://localhost:8545",
        },
        timeout_seconds: {
          type: "number",
          description:
            "Max seconds to wait for decompilation (default: 120). Large contracts may need more.",
        },
      },
      required: ["target"],
    },
  },

  {
    name: "analyze_contract_security",
    description: `Perform a comprehensive security audit of smart contract source or decompiled code using Claude.

Covers 13 vulnerability classes including:
- Reentrancy (single, cross-function, cross-contract, ERC777)
- Access control (missing checks, tx.origin, unprotected initializers)
- Arithmetic (overflow, underflow, precision loss, rounding)
- Flash loan & oracle price manipulation
- Proxy/upgrade pattern issues (storage collisions, uninitialized impls)
- External call risks (unchecked returns, delegatecall to arbitrary addresses)
- DoS vectors (gas limit loops, forced ETH, griefing)
- Front-running & MEV exposure
- Signature replay attacks
- Token standard compliance issues
- Block/timestamp manipulation
- Centralization & trust risks
- DeFi-specific patterns (liquidation, vault inflation, interest accounting)

Returns a structured Markdown report with severity-ranked findings and recommendations.`,
    inputSchema: {
      type: "object",
      properties: {
        code: {
          type: "string",
          description:
            "Solidity source code or decompiled pseudo-Solidity to analyze",
        },
        contract_address: {
          type: "string",
          description: "Optional: contract address for report context",
        },
        rpc_url: {
          type: "string",
          description: "Optional: network RPC URL for report context",
        },
        extra_context: {
          type: "string",
          description:
            "Optional: additional context about the contract (protocol name, intended behaviour, known issues, etc.)",
        },
      },
      required: ["code"],
    },
  },

  {
    name: "full_audit",
    description: `All-in-one: decompile a contract with Heimdall then immediately run a full Claude security audit on the output.

Combines decompile_contract + analyze_contract_security in a single call.
Use this when you have a contract address or bytecode and want the complete audit without intermediate steps.`,
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Contract address (0x...) or raw hex bytecode",
        },
        rpc_url: {
          type: "string",
          description:
            "JSON-RPC endpoint (required for address targets)",
        },
        extra_context: {
          type: "string",
          description:
            "Optional context about the contract or protocol to enrich the analysis",
        },
        timeout_seconds: {
          type: "number",
          description: "Max seconds for decompilation step (default: 120)",
        },
      },
      required: ["target"],
    },
  },

  {
    name: "check_heimdall",
    description:
      "Check whether the Heimdall CLI is installed and available in PATH. Run this first if decompilation fails.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
];

// ─── Server Setup ─────────────────────────────────────────────────────────────

const server = new Server(
  {
    name: "heimdall-audit-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// ─── Tool List Handler ────────────────────────────────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools: TOOLS };
});

// ─── Tool Call Handler ────────────────────────────────────────────────────────

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      // ── check_heimdall ──────────────────────────────────────────────────
      case "check_heimdall": {
        const status = checkHeimdall();
        if (status.available) {
          return {
            content: [
              {
                type: "text",
                text: `✅ Heimdall is available.\nVersion: ${status.version}\n\nReady to decompile contracts.`,
              },
            ],
          };
        } else {
          return {
            content: [
              {
                type: "text",
                text: `❌ Heimdall is NOT available in PATH.\n\nError: ${status.error}\n\n## Installation\n\nInstall via cargo:\n\`\`\`bash\ncargo install heimdall-rs\n\`\`\`\n\nOr via the install script:\n\`\`\`bash\ncurl -sS https://raw.githubusercontent.com/Jon-Becker/heimdall-rs/main/scripts/install.sh | bash\n\`\`\`\n\nAfter install, ensure the binary is in your PATH.`,
              },
            ],
          };
        }
      }

      // ── decompile_contract ──────────────────────────────────────────────
      case "decompile_contract": {
        const target = String(args?.target ?? "").trim();
        const rpcUrl = args?.rpc_url ? String(args.rpc_url) : undefined;
        const timeoutMs = args?.timeout_seconds
          ? Number(args.timeout_seconds) * 1000
          : 120_000;

        if (!target) {
          return {
            content: [{ type: "text", text: "Error: `target` is required." }],
            isError: true,
          };
        }

        const result = await decompileContract(target, rpcUrl, timeoutMs);

        if (!result.success) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Decompilation failed.\n\n**Error:** ${result.error}\n\n${result.rawOutput ? `**Heimdall output:**\n\`\`\`\n${result.rawOutput.slice(0, 3000)}\n\`\`\`` : ""}`,
              },
            ],
            isError: true,
          };
        }

        let output = `✅ Decompilation successful.\n\n`;
        if (result.abi) {
          output += `## Recovered ABI\n\`\`\`json\n${result.abi}\n\`\`\`\n\n`;
        }
        output += `## Decompiled Source\n\`\`\`solidity\n${result.code}\n\`\`\``;

        return { content: [{ type: "text", text: output }] };
      }

      // ── analyze_contract_security ───────────────────────────────────────
      case "analyze_contract_security": {
        const code = String(args?.code ?? "").trim();
        const contractAddress = args?.contract_address
          ? String(args.contract_address)
          : undefined;
        const rpcUrl = args?.rpc_url ? String(args.rpc_url) : undefined;
        const extraContext = args?.extra_context
          ? String(args.extra_context)
          : undefined;

        if (!code) {
          return {
            content: [{ type: "text", text: "Error: `code` is required." }],
            isError: true,
          };
        }

        const result = await analyzeContractSecurity(
          code,
          contractAddress,
          rpcUrl,
          extraContext
        );

        if (!result.success) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Analysis failed.\n\n**Error:** ${result.error}`,
              },
            ],
            isError: true,
          };
        }

        const tokenNote =
          result.inputTokens !== undefined
            ? `\n\n---\n*Analysis used ${result.inputTokens.toLocaleString()} input tokens and ${result.outputTokens?.toLocaleString()} output tokens.*`
            : "";

        return {
          content: [
            {
              type: "text",
              text: `${result.report}${tokenNote}`,
            },
          ],
        };
      }

      // ── full_audit ──────────────────────────────────────────────────────
      case "full_audit": {
        const target = String(args?.target ?? "").trim();
        const rpcUrl = args?.rpc_url ? String(args.rpc_url) : undefined;
        const extraContext = args?.extra_context
          ? String(args.extra_context)
          : undefined;
        const timeoutMs = args?.timeout_seconds
          ? Number(args.timeout_seconds) * 1000
          : 120_000;

        if (!target) {
          return {
            content: [{ type: "text", text: "Error: `target` is required." }],
            isError: true,
          };
        }

        // Step 1 — Decompile
        const decompResult = await decompileContract(target, rpcUrl, timeoutMs);

        if (!decompResult.success || !decompResult.code) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Decompilation failed — cannot proceed to audit.\n\n**Error:** ${decompResult.error}\n\n${decompResult.rawOutput ? `**Heimdall output:**\n\`\`\`\n${decompResult.rawOutput.slice(0, 2000)}\n\`\`\`` : ""}`,
              },
            ],
            isError: true,
          };
        }

        // Step 2 — Analyze
        const analysisResult = await analyzeContractSecurity(
          decompResult.code,
          target,
          rpcUrl,
          extraContext
        );

        if (!analysisResult.success) {
          return {
            content: [
              {
                type: "text",
                text: `✅ Decompilation succeeded, but analysis failed.\n\n**Error:** ${analysisResult.error}\n\n## Decompiled Code (for manual review)\n\`\`\`solidity\n${decompResult.code}\n\`\`\``,
              },
            ],
            isError: true,
          };
        }

        const abiSection = decompResult.abi
          ? `## Recovered ABI\n\`\`\`json\n${decompResult.abi}\n\`\`\`\n\n`
          : "";

        const tokenNote =
          analysisResult.inputTokens !== undefined
            ? `\n\n---\n*Analysis used ${analysisResult.inputTokens.toLocaleString()} input tokens and ${analysisResult.outputTokens?.toLocaleString()} output tokens.*`
            : "";

        return {
          content: [
            {
              type: "text",
              text: `${abiSection}## Security Audit Report\n\n${analysisResult.report}${tokenNote}`,
            },
          ],
        };
      }

      // ── unknown ─────────────────────────────────────────────────────────
      default:
        return {
          content: [{ type: "text", text: `Unknown tool: ${name}` }],
          isError: true,
        };
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      content: [{ type: "text", text: `Unhandled error in tool "${name}": ${msg}` }],
      isError: true,
    };
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // MCP servers communicate via stdio — all logs go to stderr
  process.stderr.write("heimdall-audit-mcp server started\n");
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err}\n`);
  process.exit(1);
});
