import { describe, test, expect } from 'bun:test';
import { getToolRisk, resolveEnabledToolNames } from './tool-risk.js';
import { generatedTools } from './tools.js';

describe('getToolRisk', () => {
  test('every tool in the generated set resolves to a classification', () => {
    for (const tool of generatedTools) {
      const entry = getToolRisk(tool.name);
      expect(['read', 'write', 'destructive', 'administrative']).toContain(entry.risk);
      expect(['safe', 'advanced', 'administrative']).toContain(entry.requiredPreset);
    }
  });

  test('an unknown tool name falls back to the most restrictive classification', () => {
    const entry = getToolRisk('this_tool_does_not_exist_and_never_will');
    expect(entry.requiredPreset).toBe('administrative');
    expect(entry.risk).toBe('administrative');
    expect(entry.requiresConfirmation).toBe(true);
  });

  test('spot-check: explicit safe-preset examples from the hardening spec', () => {
    for (const name of ['list_account', 'get_account', 'search_accounts', 'list_transaction', 'search_transactions', 'store_transaction', 'update_transaction', 'store_category', 'store_tag', 'get_basic_summary']) {
      expect(getToolRisk(name).requiredPreset).toBe('safe');
    }
  });

  test('spot-check: explicit advanced-preset examples from the hardening spec', () => {
    for (const name of ['delete_transaction', 'store_bill', 'delete_bill', 'store_budget', 'delete_budget', 'store_piggy_bank', 'delete_piggy_bank', 'store_recurrence', 'store_attachment', 'store_rule']) {
      expect(getToolRisk(name).requiredPreset).toBe('advanced');
    }
  });

  test('spot-check: explicit administrative-preset examples from the hardening spec', () => {
    for (const name of ['destroy_data', 'purge_data', 'store_user', 'delete_user', 'set_configuration', 'store_currency', 'store_webhook', 'delete_webhook', 'bulk_update_transactions']) {
      expect(getToolRisk(name).requiredPreset).toBe('administrative');
    }
  });

  test('destructive and administrative tools are flagged as requiring confirmation', () => {
    expect(getToolRisk('delete_transaction').requiresConfirmation).toBe(true);
    expect(getToolRisk('destroy_data').requiresConfirmation).toBe(true);
    expect(getToolRisk('list_account').requiresConfirmation).toBe(false);
  });

  test('destroy_data and purge_data are flagged as permanently deleting data', () => {
    expect(getToolRisk('destroy_data').permanentlyDeletesData).toBe(true);
    expect(getToolRisk('purge_data').permanentlyDeletesData).toBe(true);
    expect(getToolRisk('delete_account').permanentlyDeletesData).toBe(true);
    expect(getToolRisk('list_account').permanentlyDeletesData).toBe(false);
  });
});

describe('resolveEnabledToolNames: preset gating', () => {
  test('safe preset excludes every advanced and administrative tool', () => {
    const enabled = resolveEnabledToolNames(generatedTools, { preset: 'safe', includeAdmin: false });
    for (const name of ['delete_transaction', 'store_bill', 'destroy_data', 'store_user']) {
      expect(enabled.has(name)).toBe(false);
    }
    expect(enabled.has('list_account')).toBe(true);
    expect(enabled.has('store_transaction')).toBe(true);
  });

  test('advanced preset is a strict superset of safe and still excludes administrative tools', () => {
    const safe = resolveEnabledToolNames(generatedTools, { preset: 'safe', includeAdmin: false });
    const advanced = resolveEnabledToolNames(generatedTools, { preset: 'advanced', includeAdmin: false });
    for (const name of safe) expect(advanced.has(name)).toBe(true);
    expect(advanced.has('delete_transaction')).toBe(true);
    expect(advanced.has('store_bill')).toBe(true);
    for (const name of ['destroy_data', 'purge_data', 'store_user', 'delete_user']) {
      expect(advanced.has(name)).toBe(false);
    }
  });

  test('administrative tools stay disabled even under advanced preset with includeAdmin=false', () => {
    const enabled = resolveEnabledToolNames(generatedTools, { preset: 'advanced', includeAdmin: false });
    expect(enabled.has('destroy_data')).toBe(false);
  });

  test('includeAdmin alone (no allowlist) enables nothing administrative', () => {
    const enabled = resolveEnabledToolNames(generatedTools, { preset: 'safe', includeAdmin: true });
    expect(enabled.has('destroy_data')).toBe(false);
    expect(enabled.has('store_user')).toBe(false);
  });

  test('includeAdmin + an explicit allowlist enables only the named administrative tools', () => {
    const enabled = resolveEnabledToolNames(generatedTools, {
      preset: 'safe', includeAdmin: true, adminToolAllowlist: ['store_user'],
    });
    expect(enabled.has('store_user')).toBe(true);
    expect(enabled.has('delete_user')).toBe(false); // named tool only, not the whole administrative tier
    expect(enabled.has('destroy_data')).toBe(false);
  });

  test('every enabled tool name actually exists in generatedTools (no dangling entries)', () => {
    const validNames = new Set(generatedTools.map((t: { name: string }) => t.name));
    const enabled = resolveEnabledToolNames(generatedTools, { preset: 'advanced', includeAdmin: true, adminToolAllowlist: ['destroy_data'] });
    for (const name of enabled) expect(validNames.has(name)).toBe(true);
  });
});
