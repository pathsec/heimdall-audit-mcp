import Anthropic from "@anthropic-ai/sdk";
import { SECURITY_SYSTEM_PROMPT, ANALYSIS_USER_TEMPLATE } from "./security-prompt.js";

export interface AnalysisResult {
  success: boolean;
  report?: string;
  inputTokens?: number;
  outputTokens?: number;
  error?: string;
}

const MODEL = "claude-sonnet-4-20250514";

/**
 * Run a full security audit of decompiled smart contract code using Claude.
 *
 * @param decompiledCode  The pseudo-Solidity code from Heimdall
 * @param contractAddress Optional — included in the report for context
 * @param rpcUrl          Optional — noted in the report
 * @param extraContext    Optional — any additional context the caller wants to inject
 * @param apiKey          Anthropic API key (falls back to ANTHROPIC_API_KEY env var)
 */
export async function analyzeContractSecurity(
  decompiledCode: string,
  contractAddress?: string,
  rpcUrl?: string,
  extraContext?: string,
  apiKey?: string
): Promise<AnalysisResult> {
  const client = new Anthropic({
    apiKey: apiKey ?? process.env.ANTHROPIC_API_KEY,
  });

  const userMessage = ANALYSIS_USER_TEMPLATE(
    contractAddress,
    rpcUrl,
    decompiledCode,
    extraContext
  );

  try {
    const response = await client.messages.create({
      model: MODEL,
      max_tokens: 8192,
      system: SECURITY_SYSTEM_PROMPT,
      messages: [
        {
          role: "user",
          content: userMessage,
        },
      ],
    });

    const textBlock = response.content.find((b) => b.type === "text");
    if (!textBlock || textBlock.type !== "text") {
      return { success: false, error: "Claude returned no text content" };
    }

    return {
      success: true,
      report: textBlock.text,
      inputTokens: response.usage.input_tokens,
      outputTokens: response.usage.output_tokens,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: `Anthropic API error: ${msg}` };
  }
}
