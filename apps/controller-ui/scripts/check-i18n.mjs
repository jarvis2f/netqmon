import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const messagesDir = path.resolve(__dirname, "../i18n/messages");
const enPath = path.join(messagesDir, "en.json");
const zhPath = path.join(messagesDir, "zh-CN.json");

function readJson(filepath) {
  if (!fs.existsSync(filepath)) {
    console.error(`File does not exist: ${filepath}`);
    process.exit(1);
  }
  const content = fs.readFileSync(filepath, "utf-8");
  return JSON.parse(content);
}

function getLeafKeys(obj, prefix = "") {
  let keys = [];
  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      keys = keys.concat(getLeafKeys(value, fullKey));
    } else {
      keys.push({ key: fullKey, value });
    }
  }
  return keys;
}

const en = readJson(enPath);
const zh = readJson(zhPath);

const enLeaves = getLeafKeys(en);
const zhLeaves = getLeafKeys(zh);

const enKeyMap = new Map(enLeaves.map((item) => [item.key, item.value]));
const zhKeyMap = new Map(zhLeaves.map((item) => [item.key, item.value]));

let hasError = false;

// Check missing in zh-CN
for (const [key] of enKeyMap.entries()) {
  if (!zhKeyMap.has(key)) {
    console.error(`[MISSING in zh-CN] ${key}`);
    hasError = true;
  } else if (
    typeof zhKeyMap.get(key) === "string" &&
    zhKeyMap.get(key).trim() === ""
  ) {
    console.error(`[EMPTY in zh-CN] ${key}`);
    hasError = true;
  }
}

// Check extra in zh-CN
for (const [key] of zhKeyMap.entries()) {
  if (!enKeyMap.has(key)) {
    console.error(`[EXTRA in zh-CN] ${key}`);
    hasError = true;
  }
}

if (hasError) {
  console.error(`\n❌ i18n parity check failed!`);
  process.exit(1);
} else {
  console.log(
    `✅ i18n parity check passed: ${enLeaves.length} keys in en.json match zh-CN.json perfectly.`,
  );
}
