/**
 * Generates src/tool-risk-map.generated.ts from the current generatedTools
 * list (src/tools.ts), so re-running `npm run toolgen` against a newer
 * Firefly III spec doesn't silently leave new tools unclassified.
 *
 * Classification is rule-based (resource tag + verb), with a small set of
 * name-level overrides for tools the tag+verb rules can't express correctly
 * (autocomplete tools, which only carry the 'autocomplete' tag; the handful
 * of system-wide/irregularly-named endpoints). Every one of the 219 current
 * tools gets an explicit entry — this is deliberate: a fully-enumerated map
 * is easier to review and correct by hand than a purely rule-driven one.
 * Tools this generator has never seen (e.g. added by a future spec bump)
 * are NOT written here; tool-risk.ts's runtime lookup falls back to the
 * most restrictive classification (administrative) for anything missing
 * from this map, so an unclassified new tool never becomes reachable
 * through the 'safe' or 'advanced' presets by accident.
 *
 * Every generated line is tagged with the rule that produced it (see the
 * trailing comment above each entry) so a reviewer can tell "this was an
 * explicit category from the hardening spec" apart from "this fell out of
 * a generic tag rule and deserves a second look."
 */
import fs from 'node:fs';
import { generatedTools } from '../src/tools.js';
import type { McpToolDefinition } from '../src/types.js';
import type { ToolRisk, ToolPreset } from '../src/tool-risk-types.js';

const OUTPUT_FILE = './src/tool-risk-map.generated.ts';

type Classification = { risk: ToolRisk; preset: ToolPreset; reason: string };

// Tags that are entirely one tier regardless of verb.
const WHOLE_RESOURCE_SAFE = new Set(['about', 'search', 'summary', 'insight', 'charts']);
const WHOLE_RESOURCE_ADVANCED = new Set([
  'bills', 'piggy_banks', 'recurrences', 'rules', 'rule_groups',
  'attachments', 'currency_exchange_rates', 'links', 'object_groups', 'preferences',
]);
const WHOLE_RESOURCE_ADMIN = new Set(['configuration', 'data', 'users', 'user_groups', 'webhooks']);

// Tags that split by verb: reads are one tier, writes/deletes another.
const SPLIT_TAGS = new Set([
  'accounts', 'transactions', 'categories', 'tags', 'budgets', 'available_budgets', 'currencies',
]);
const READ_VERBS = new Set(['get', 'list', 'search']);
const WRITE_VERBS = new Set(['store', 'update']);
const DELETE_VERBS = new Set(['delete']);
// Only 'categories' and 'tags' explicitly call out *creation* as safe in the
// hardening spec ("Create categories", "Create tags") without also calling
// update/delete safe - so those two get a bespoke create-is-safe rule.
const STORE_ONLY_SAFE = new Set(['categories', 'tags']);

const SPLIT_RULES: Record<string, { read: [ToolRisk, ToolPreset]; write: [ToolRisk, ToolPreset]; delete: [ToolRisk, ToolPreset] }> = {
  accounts: { read: ['read', 'safe'], write: ['write', 'advanced'], delete: ['destructive', 'advanced'] },
  transactions: { read: ['read', 'safe'], write: ['write', 'safe'], delete: ['destructive', 'advanced'] },
  categories: { read: ['read', 'safe'], write: ['write', 'safe'], delete: ['destructive', 'advanced'] },
  tags: { read: ['read', 'safe'], write: ['write', 'safe'], delete: ['destructive', 'advanced'] },
  budgets: { read: ['read', 'safe'], write: ['write', 'advanced'], delete: ['destructive', 'advanced'] },
  available_budgets: { read: ['read', 'safe'], write: ['write', 'advanced'], delete: ['destructive', 'advanced'] },
  currencies: { read: ['read', 'advanced'], write: ['write', 'administrative'], delete: ['destructive', 'administrative'] },
};

// Name-level exceptions the tag+verb rules can't express correctly.
const NAME_OVERRIDES: Record<string, [ToolRisk, ToolPreset]> = {
  destroy_data: ['administrative', 'administrative'],
  purge_data: ['administrative', 'administrative'],
  bulk_update_transactions: ['administrative', 'administrative'],
  get_cron: ['administrative', 'administrative'],
  delete_user: ['administrative', 'administrative'],
  delete_transaction_journal: ['destructive', 'advanced'],
  upload_attachment: ['write', 'advanced'],
  set_configuration: ['write', 'administrative'],
  fire_rule: ['write', 'advanced'],
  fire_rule_group: ['write', 'advanced'],
  submit_webook: ['write', 'administrative'],
  trigger_transaction_webhook: ['write', 'administrative'],
};

// Autocomplete tools (get_*_ac / get_*_idac) only carry the 'autocomplete'
// tag in the generated spec, so their tier has to come from a resource
// keyword embedded in the name itself.
const AC_RESOURCE_TIER: Record<string, ToolPreset> = {
  accounts: 'safe', bills: 'advanced', budgets: 'safe', categories: 'safe',
  currencies_code: 'advanced', currencies: 'advanced', object_groups: 'advanced',
  piggies_balance: 'advanced', piggies: 'advanced', recurring: 'advanced',
  rule_groups: 'advanced', rules: 'advanced', tag: 'safe',
  transaction_types: 'safe', transactions_id: 'safe', transactions: 'safe',
};

const classify = (tool: McpToolDefinition): Classification => {
  const { name, tags } = tool;

  if (name in NAME_OVERRIDES) {
    const [risk, preset] = NAME_OVERRIDES[name];
    return { risk, preset, reason: 'name-override' };
  }

  if (name.startsWith('export_')) {
    // Tagged 'data' alongside destroy_data/purge_data, but read-only bulk
    // CSV export of the user's own single-tenant data - not destructive or
    // system-wide, so advanced (bulk egress) rather than administrative.
    return { risk: 'read', preset: 'advanced', reason: 'name-override:export' };
  }

  if (tags.includes('autocomplete')) {
    const stem = (name.startsWith('get_') ? name.slice(4) : name).replace(/_idac$|_ac$/, '');
    const key = Object.keys(AC_RESOURCE_TIER)
      .sort((a, b) => b.length - a.length)
      .find((k) => stem.startsWith(k) || stem.includes(k));
    if (key) return { risk: 'read', preset: AC_RESOURCE_TIER[key], reason: `autocomplete->${key}` };
    return { risk: 'read', preset: 'advanced', reason: 'autocomplete-fallback' };
  }

  const tag = tags[0];
  const verb = name.split('_')[0];

  if (tag && WHOLE_RESOURCE_SAFE.has(tag)) {
    return { risk: 'read', preset: 'safe', reason: `tag:${tag}` };
  }
  if (tag && WHOLE_RESOURCE_ADVANCED.has(tag)) {
    const risk: ToolRisk = DELETE_VERBS.has(verb) ? 'destructive' : WRITE_VERBS.has(verb) ? 'write' : 'read';
    return { risk, preset: 'advanced', reason: `tag:${tag}` };
  }
  if (tag && WHOLE_RESOURCE_ADMIN.has(tag)) {
    const risk: ToolRisk = DELETE_VERBS.has(verb) ? 'destructive' : WRITE_VERBS.has(verb) ? 'write' : 'read';
    return { risk, preset: 'administrative', reason: `tag:${tag}` };
  }
  if (tag && SPLIT_TAGS.has(tag)) {
    const bucket: 'read' | 'write' | 'delete' = READ_VERBS.has(verb) ? 'read' : DELETE_VERBS.has(verb) ? 'delete' : 'write';
    if (STORE_ONLY_SAFE.has(tag)) {
      if (verb === 'store') return { risk: 'write', preset: 'safe', reason: `split:${tag}:create-safe` };
      if (verb === 'update') return { risk: 'write', preset: 'advanced', reason: `split:${tag}:update-advanced` };
    }
    const [risk, preset] = SPLIT_RULES[tag][bucket];
    return { risk, preset, reason: `split:${tag}:${bucket}` };
  }

  // True fallback: nothing matched - default to the most restrictive tier
  // so a tool this generator genuinely doesn't understand never lands in
  // 'safe' or 'advanced' by accident.
  return { risk: 'administrative', preset: 'administrative', reason: 'UNCLASSIFIED-fallback' };
};

const MOVES_MONEY = new Set([
  'store_transaction', 'update_transaction', 'delete_transaction', 'delete_transaction_journal',
  'fire_rule', 'fire_rule_group', 'bulk_update_transactions',
]);
const AFFECTS_OTHER_USERS_TAGS = new Set(['users', 'user_groups', 'webhooks', 'data']);

const movesMoney = (tool: McpToolDefinition): boolean => MOVES_MONEY.has(tool.name);
const permanentlyDeletesData = (tool: McpToolDefinition): boolean =>
  tool.name.startsWith('delete_') || tool.name === 'destroy_data' || tool.name === 'purge_data';
const affectsOtherUsers = (tool: McpToolDefinition): boolean =>
  tool.tags.some((t) => AFFECTS_OTHER_USERS_TAGS.has(t));
const requiresConfirmation = (risk: ToolRisk, preset: ToolPreset): boolean =>
  risk === 'destructive' || risk === 'administrative' || preset === 'administrative';

const sorted = [...generatedTools].sort((a, b) => a.name.localeCompare(b.name));

let unclassified = 0;
const lines: string[] = [
  '// AUTO-GENERATED by scripts/generate-tool-risk.ts - do not hand-edit.',
  '// Regenerate with `npx tsx scripts/generate-tool-risk.ts` after `npm run toolgen`',
  "// picks up new/changed tools from the Firefly III OpenAPI spec, then review any",
  "// entries whose comment says UNCLASSIFIED-fallback or *-fallback before trusting them.",
  "import type { ToolRiskEntry } from './tool-risk-types.js';",
  '',
  'export const TOOL_RISK_MAP: Record<string, ToolRiskEntry> = {',
];

for (const tool of sorted) {
  const { risk, preset, reason } = classify(tool);
  if (reason.includes('fallback')) unclassified += 1;
  const entry: Record<string, unknown> = {
    risk,
    requiredPreset: preset,
    movesMoney: movesMoney(tool),
    permanentlyDeletesData: permanentlyDeletesData(tool),
    affectsOtherUsers: affectsOtherUsers(tool),
    requiresConfirmation: requiresConfirmation(risk, preset),
  };
  lines.push(`  // ${reason}`);
  lines.push(
    `  ${tool.name}: { risk: '${entry.risk}', requiredPreset: '${entry.requiredPreset}', movesMoney: ${entry.movesMoney}, permanentlyDeletesData: ${entry.permanentlyDeletesData}, affectsOtherUsers: ${entry.affectsOtherUsers}, requiresConfirmation: ${entry.requiresConfirmation} },`,
  );
}
lines.push('};');
lines.push('');

fs.writeFileSync(OUTPUT_FILE, lines.join('\n'));
console.log(`Wrote ${sorted.length} tool risk entries to ${OUTPUT_FILE} (${unclassified} via fallback rules).`);
