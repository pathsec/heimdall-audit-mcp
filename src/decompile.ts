import { spawnSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

export interface DecompileResult {
  success: boolean;
  code?: string;
  abi?: string;
  error?: string;
  rawOutput?: string;
}

/**
 * Checks if heimdall is installed and returns its version.
 */
export function checkHeimdall(): { available: boolean; version?: string; error?: string } {
  try {
    const result = spawnSync("heimdall", ["--version"], {
      encoding: "utf-8",
      timeout: 10_000,
    });
    if (result.status === 0) {
      return { available: true, version: result.stdout.trim() };
    }
    return { available: false, error: result.stderr || "Non-zero exit" };
  } catch (e) {
    return { available: false, error: String(e) };
  }
}

/**
 * Decompile an on-chain contract (by address) or raw bytecode using heimdall-rs.
 *
 * @param target   Contract address (0x...) or raw hex bytecode
 * @param rpcUrl   RPC endpoint — required when target is an address
 * @param timeout  Max ms to wait (default 120s — decompilation can be slow)
 */
export async function decompileContract(
  target: string,
  rpcUrl?: string,
  timeout = 120_000
): Promise<DecompileResult> {
  // Determine whether we have an address or raw bytecode
  const isAddress = /^0x[0-9a-fA-F]{40}$/.test(target.trim());
  const isBytecode = /^(0x)?[0-9a-fA-F]+$/.test(target.trim()) && target.length > 42;

  if (!isAddress && !isBytecode) {
    return {
      success: false,
      error: `Invalid target: "${target}". Provide a 20-byte address (0x...) or raw hex bytecode.`,
    };
  }

  if (isAddress && !rpcUrl) {
    return {
      success: false,
      error: "An RPC URL is required when decompiling by contract address.",
    };
  }

  // Build the temp output directory
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "heimdall-"));

  try {
    // Build args
    // heimdall decompile <target> [--rpc-url <url>] --output <dir> --include-sol --include-yul
    const args: string[] = [
      "decompile",
      isAddress ? target.trim() : target.trim(),
      "--output",
      tmpDir,
      "--include-sol",   // Output reconstructed Solidity
      "--default",       // Auto-confirm all prompts (non-interactive)
    ];

    if (isAddress && rpcUrl) {
      args.push("--rpc-url", rpcUrl);
    }

    const result = spawnSync("heimdall", args, {
      encoding: "utf-8",
      timeout,
      maxBuffer: 64 * 1024 * 1024, // 64MB
    });

    const rawOutput = `STDOUT:\n${result.stdout}\n\nSTDERR:\n${result.stderr}`;

    if (result.error) {
      // e.g. ENOENT (heimdall not found) or ETIMEDOUT
      return {
        success: false,
        error: `Heimdall process error: ${result.error.message}`,
        rawOutput,
      };
    }

    // Try to find the decompiled .sol file in tmpDir
    const solFile = findFileRecursive(tmpDir, ".sol");
    const abiFile = findFileRecursive(tmpDir, ".json");

    if (solFile) {
      const code = fs.readFileSync(solFile, "utf-8");
      const abi = abiFile ? fs.readFileSync(abiFile, "utf-8") : undefined;
      return {
        success: true,
        code,
        abi,
        rawOutput,
      };
    }

    // If no sol file, fall back to stdout (some versions print directly)
    if (result.stdout && result.stdout.trim().length > 50) {
      return {
        success: true,
        code: result.stdout.trim(),
        rawOutput,
      };
    }

    return {
      success: false,
      error: `Heimdall ran but produced no output.\n\nExit code: ${result.status}\n\n${rawOutput}`,
      rawOutput,
    };
  } finally {
    // Clean up temp dir
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* ignore cleanup errors */
    }
  }
}

function findFileRecursive(dir: string, ext: string): string | null {
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        const found = findFileRecursive(full, ext);
        if (found) return found;
      } else if (entry.name.endsWith(ext)) {
        return full;
      }
    }
  } catch {
    /* ignore */
  }
  return null;
}
