import { dump, JSON_SCHEMA, load, type YAMLException } from "js-yaml";
import type { PolicySpecV1 } from "@/lib/network-types";

export class PolicyYamlError extends Error {
  constructor(
    message: string,
    readonly line?: number,
    readonly column?: number,
  ) {
    super(message);
    this.name = "PolicyYamlError";
  }
}

export function parsePolicyYaml(source: string): PolicySpecV1 {
  if (new TextEncoder().encode(source).byteLength > 64 * 1024) {
    throw new PolicyYamlError("YAML input exceeds 64 KiB");
  }
  preflightYaml(source);
  let value: unknown;
  try {
    value = load(source, { schema: JSON_SCHEMA, json: false });
  } catch (error) {
    const yamlError = error as YAMLException;
    throw new PolicyYamlError(
      yamlError.message,
      yamlError.mark ? yamlError.mark.line + 1 : undefined,
      yamlError.mark ? yamlError.mark.column + 1 : undefined,
    );
  }
  assertPlainData(value, 0);
  return value as PolicySpecV1;
}

export function formatPolicyYaml(spec: PolicySpecV1) {
  return dump(spec, { lineWidth: 100, noRefs: true, sortKeys: false });
}

function assertPlainData(value: unknown, depth: number): void {
  if (depth > 32) throw new PolicyYamlError("YAML nesting exceeds 32 levels");
  if (value === null || ["string", "number", "boolean"].includes(typeof value))
    return;
  if (Array.isArray(value)) {
    value.forEach((item) => assertPlainData(item, depth + 1));
    return;
  }
  if (
    typeof value !== "object" ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new PolicyYamlError(
      "Only plain YAML mappings and scalar values are supported",
    );
  }
  for (const [key, child] of Object.entries(value)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      throw new PolicyYamlError(`Unsafe mapping key: ${key}`);
    }
    assertPlainData(child, depth + 1);
  }
}

function preflightYaml(source: string) {
  const lines = source.split(/\r?\n/);
  let quote: "single" | "double" | null = null;
  let flowDepth = 0;

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex];
    if ((line.match(/^ */)?.[0].length ?? 0) > 64) {
      throw new PolicyYamlError(
        "YAML indentation exceeds 64 spaces",
        lineIndex + 1,
      );
    }
    let previousOnLine: string | null = null;
    for (let index = 0; index < line.length; index += 1) {
      const character = line[index];
      if (quote === "double") {
        if (character === "\\") index += 1;
        else if (character === '"') quote = null;
        continue;
      }
      if (quote === "single") {
        if (character === "'" && line[index + 1] === "'") index += 1;
        else if (character === "'") quote = null;
        continue;
      }
      if (character === "#" && (index === 0 || /\s/.test(line[index - 1]))) {
        break;
      }
      if (character === '"') {
        quote = "double";
        continue;
      }
      if (character === "'") {
        quote = "single";
        continue;
      }
      if (character === "[" || character === "{") {
        flowDepth += 1;
        if (flowDepth > 32)
          throw new PolicyYamlError(
            "YAML nesting exceeds 32 levels",
            lineIndex + 1,
          );
      } else if (character === "]" || character === "}") {
        flowDepth = Math.max(0, flowDepth - 1);
      }
      if (["&", "*", "!"].includes(character)) {
        const next = line[index + 1];
        const boundary =
          previousOnLine === null ||
          [":", "-", "[", "{", ",", "?"].includes(previousOnLine);
        if (boundary && next && !/\s/.test(next)) {
          const feature =
            character === "&"
              ? "anchors"
              : character === "*"
                ? "aliases"
                : "custom tags";
          throw new PolicyYamlError(
            `YAML ${feature} are not supported`,
            lineIndex + 1,
            index + 1,
          );
        }
      }
      if (!/\s/.test(character)) previousOnLine = character;
    }
  }
}
