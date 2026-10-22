declare module "js-yaml" {
  export interface YAMLMark {
    line: number;
    column: number;
  }

  export interface YAMLException extends Error {
    mark?: YAMLMark;
  }

  export const JSON_SCHEMA: unknown;

  export function load(
    source: string,
    options?: { schema?: unknown; json?: boolean },
  ): unknown;

  export function dump(
    value: unknown,
    options?: {
      lineWidth?: number;
      noRefs?: boolean;
      sortKeys?: boolean;
    },
  ): string;
}
