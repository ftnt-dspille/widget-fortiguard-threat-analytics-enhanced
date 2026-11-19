'use strict';
// E2E for the analytics demo view's failure handling. The connector's
// integration endpoints are stubbed at the browser level (page.route) with
// payloads shaped like the live feed, so the hermetic tier sees no
// un-stubbed proxy call. The failure test fulfills the execute endpoint with
// HTTP 500: a failed request must show the retry state and NEVER the
// "No data for this filter" message (a transient FortiGuard blip once blanked
// every card with that false claim).
//
//   make test-e2e-spec WIDGET=fortiGuardThreatAnalyticsDemo

const { test, expect } = require('../../../../fortisoar-widget-harness/tests/e2e/_fixtures');
const { mountWidget } = require('../../../../fortisoar-widget-harness/tests/e2e/_widgetHarness');

const LOGTIME = '2026-11-19 00:44';

function statsEnv(rows) {
  return [{ Logtime: LOGTIME, Stats: rows }];
}

function fixtureData(op, params) {
  params = params || {};
  const win = Number(params.time_windows || 7);
  if (op === 'get_industry_list') {
    return ['Healthcare', 'Empty', 'Education', 'Aerospace & Defense'];
  }
  if (op === 'top_threats' || op === 'top_threats_by_country') {
    const virus = params.threat_type === 'Malware';
    const names = virus
      ? ['W32/BackDoor.Prosiak', 'HTML/Phish.Tag', 'MSExcel/CVE_2017_0199', 'PossibleThreat.RF', 'Riskware/CoinMiner']
      : ['DNS.PTR.Records.Scan', 'HTTP.Suspicious.Headers', 'SIPVicious.SIP.Scanner', 'Modbus.TCP.Unauthorized.Read', 'TCP.Out.Of.Range.Timestamp'];
    return statsEnv(names.map((n, i) => ({ Name: n, ID: 1000 + i, Threattype: virus ? 'virus' : 'ips', Count: Math.round(1e9 / (i + 1)) })));
  }
  if (op === 'top_threat_countries' || op === 'threat_activities_statistics_by_country') {
    return statsEnv(['US', 'VN', 'IN', 'NZ', 'CH', 'ID'].map((c, i) => ({ Country: c, Threattype: 'ips', Count: Math.round(1e10 / (i + 1)) })));
  }
  if (op === 'top_threat_industries' || op === 'top_industries_country') {
    return statsEnv(['Banking/Finance/Insurance', 'Energy & Utilities', 'Education', 'Agriculture', 'Healthcare', 'Empty', 'Consulting']
      .map((ind, i) => ({ Industry: ind, Threattype: 'virus', Count: Math.round(1e9 / (i + 1)) })));
  }
  return statsEnv([{ Count: 1000 * win, Threattype: params.threat_type || 'ips' }]);
}

// Stub both integration endpoints. `over` lets a test reroute a call.
async function installRoutes(page, over) {
  over = over || {};
  await page.route(/\/api\/integration\/connectors\//, (route) => {
    if (over.metadata) { return over.metadata(route); }
    return route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ data: [{
        name: 'fortinet-fortiguard-threat-intelligence', version: '4.2.0',
        configuration: [{ config_id: 'c9', default: true }]
      }] })
    });
  });
  await page.route(/\/api\/integration\/execute\//, (route) => {
    let body = {};
    try { body = JSON.parse(route.request().postData() || '{}'); } catch (e) { /* noop */ }
    if (over.execute) { return over.execute(route, body); }
    return route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ status: 'Success', operation: body.operation, data: fixtureData(body.operation, body.params) })
    });
  });
}

test.describe('fortiGuardThreatAnalyticsDemo -- card failure states', () => {

  test('six cards load with data and no error state', async ({ page }) => {
    await installRoutes(page);
    await mountWidget(page, 'fortiGuardThreatAnalyticsDemo', {
      config: { title: 'Analytics E2E', time_windows: 7 },
    });

    await expect(page.locator('[data-testid=tad-card]')).toHaveCount(6);
    await expect(page.locator('[data-testid=tad-card] .tad-row').first()).toBeVisible();
    await expect(page.locator('[data-testid=tad-card-error]')).toHaveCount(0);
    await expect(page.locator('[data-testid=tad-card-empty]')).toHaveCount(0);
    await expect(page.locator('.tad-asof')).toContainText(LOGTIME);
  });

  test('a failed request shows the retry state, never "No data for this filter"', async ({ page }) => {
    await installRoutes(page, {
      execute: (route) => route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ message: 'KeyError: 0' }) }),
    });
    await mountWidget(page, 'fortiGuardThreatAnalyticsDemo', {
      config: { title: 'Analytics E2E', time_windows: 7 },
    });

    // Every card names the failure and offers retry; the false "no data"
    // message never appears.
    await expect(page.locator('[data-testid=tad-card]')).toHaveCount(6);
    await expect(page.locator('[data-testid=tad-card-error]')).toHaveCount(6);
    await expect(page.locator('[data-testid=tad-card-error]').first()).toContainText("Couldn't reach FortiGuard.");
    await expect(page.locator('[data-testid=tad-card-empty]')).toHaveCount(0);
    await expect(page.getByText('No data for this filter')).toHaveCount(0);

    // The blip is over: retrying one card recovers exactly that card.
    await installRoutes(page);
    await page.locator('[data-testid=tad-card-retry]').first().click();
    const first = page.locator('[data-testid=tad-card]').first();
    await expect(first.locator('.tad-row').first()).toBeVisible();
    await expect(first.locator('[data-testid=tad-card-error]')).toHaveCount(0);
    // The other five keep their retry state until their own retry.
    await expect(page.locator('[data-testid=tad-card-error]')).toHaveCount(5);
  });
});
