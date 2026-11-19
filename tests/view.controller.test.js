"use strict";
// Unit test for the analytics demo view controller's failure handling. Boots a
// bare `cybersponse` module with the REAL service (mocked transport) and the
// controller IIFE, then asserts what the analyst gets: cards load, and a
// FAILED request is never presented as "no data" - the card carries an error
// state with a working retry (a transient FortiGuard blip once blanked every
// card with "No data for this filter").
//
//   make test-unit WIDGET=fortiGuardThreatAnalyticsDemo

global.jasmine = global.jasmine || {};
require("angular");
require("angular-mocks");

angular.module("cybersponse", []); // eslint-disable-line no-undef
require("../widget/widgetAssets/js/threatAnalyticsDemo.service.js");
require("../widget/view.controller.js");

const CTRL_NAME = "fortiGuardThreatAnalyticsDemo101DevCtrl";
const ngModule = window.angular.mock.module; // eslint-disable-line no-undef
const ngInject = window.angular.mock.inject; // eslint-disable-line no-undef

const LOGTIME = "2026-11-19 00:44";

let runAction;
let failing; // null = all succeed, true = all fail, Set = those ops fail
let emptyOps; // Set of ops that succeed with an empty Stats list
let moduleRegistered;

function fixtureFor(operation, params) {
  const win = Number((params && params.time_windows) || 7);
  if (operation === "get_industry_list") { return { data: ["Healthcare", "None"] }; }
  if (operation === "top_threats") {
    return { data: [{ Logtime: LOGTIME, Stats: [
      { Name: "DNS.PTR.Records.Scan", ID: 51391, Threattype: "ips", Count: 1000 * win },
    ] }] };
  }
  if (operation === "top_threat_countries") {
    return { data: [{ Logtime: LOGTIME, Stats: [
      { Country: "US", Count: 500 * win }, { Country: "VN", Count: 300 * win }, { Country: "IN", Count: 100 * win },
    ] }] };
  }
  if (operation === "top_threat_industries") {
    return { data: [{ Logtime: LOGTIME, Stats: [
      { Industry: "Healthcare", Count: 400 }, { Industry: "Technology", Count: 200 },
    ] }] };
  }
  if (operation === "top_threats_by_country") {
    return { data: [{ Logtime: LOGTIME, Stats: [
      { Name: "HTTP.Suspicious.Headers", ID: 999, Threattype: "ips", Count: 77 },
    ] }] };
  }
  if (operation === "top_industries_country") {
    return { data: [{ Logtime: LOGTIME, Stats: [{ Industry: "Healthcare", Count: 55 }] }] };
  }
  if (operation === "threat_activities_statistics_by_country") {
    return { data: [{ Logtime: LOGTIME, Stats: [
      { Country: "US", Count: 42, Threattype: params.threat_type, trend: null },
    ] }] };
  }
  return { data: [{ Logtime: LOGTIME, Stats: [] }] };
}

function router(operation, params) {
  if (failing === true || (failing && failing.has(operation))) {
    return Promise.reject({ data: { message: "KeyError: 0" } });
  }
  if (emptyOps && emptyOps.has(operation)) {
    return Promise.resolve({ data: [{ Logtime: LOGTIME, Stats: [] }] });
  }
  return Promise.resolve(fixtureFor(operation, params || {}));
}

// $q chains only advance on a digest; alternate real ticks with digests.
async function flush(scope, rounds) {
  for (let i = 0; i < (rounds || 6); i++) {
    await new Promise((r) => setTimeout(r, 0));
    scope.$root.$digest();
  }
}

function setup(configOver, failMode, emptyMode) {
  runAction = jest.fn();
  failing = failMode || null;
  emptyOps = emptyMode || null;
  const register = ($provide) => {
    $provide.value("API", { INTEGRATIONS: "/api/integration/" });
    $provide.value("toaster", { error: (t) => toasts.push(t.body) });
    $provide.value("widgetBasePath", "/w/");
    $provide.value("config", Object.assign({ time_windows: 7 }, configOver || {}));
    $provide.value("$rootScope", Object.assign(window.angular.injector(["ng"]).get("$rootScope"), { theme: { id: "dark" } }));
    $provide.value("$resource", () => ({
      get: () => ({ $promise: Promise.resolve({ data: [{
        name: "fortinet-fortiguard-threat-intelligence", version: "4.2.0",
        configuration: [{ config_id: "c9", default: true }],
      }] }) }),
    }));
    $provide.value("connectorService", { executeConnectorAction: (...a) => runAction(...a) });
    $provide.value("threatAnalyticsDemoUtilityService", {
      checkTranslationMode: () => Promise.resolve(),
      translate: (k) => k,
    });
  };
  if (!moduleRegistered) {
    ngModule("cybersponse", register);
    moduleRegistered = true;
  }
  runAction.mockImplementation((name, version, operation, configId, params) => router(operation, params || {}));
}

async function boot(configOver, failMode, emptyMode) {
  setup(configOver, failMode, emptyMode);
  let scope;
  let $httpBackend;
  ngInject(["$controller", "$rootScope", "$httpBackend", ($controller, $rs, $hb) => {
    $httpBackend = $hb;
    $httpBackend.whenGET(/widgetAssets\/lib\/iso2_countries\.json/).respond(200, {
      US: { map: "United States of America", name: "United States", filter: "United States" },
      VN: { map: "Vietnam", name: "Vietnam", filter: "Vietnam" },
      IN: { map: "India", name: "India", filter: "India" },
    });
    $httpBackend.whenGET(/widgetAssets\/json\/countries\.json/).respond(200, { countries: ["United States", "India"] });
    const parent = $rs.$new();
    parent.model = { type: "widget" };
    scope = parent.$new();
    $controller(CTRL_NAME, { $scope: scope });
  }]);
  const safeFlushHttp = () => { try { $httpBackend.flush(); } catch (e) { /* none pending */ } };
  safeFlushHttp();
  await flush(scope);
  safeFlushHttp();
  await flush(scope);
  return scope;
}

let toasts;
beforeEach(() => {
  moduleRegistered = false;
  toasts = [];
  jest.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => jest.restoreAllMocks());

function allCards(scope) {
  const s = scope.cardDetails;
  return [s.malware, s.vulnerabilities].reduce((acc, sec) => acc.concat([sec.threatCard, sec.countriesCard, sec.industriesCard]), []);
}

describe("on load", () => {
  test("all six cards fill and none reports an error", async () => {
    const scope = await boot();
    const cards = allCards(scope);
    expect(cards).toHaveLength(6);
    for (const c of cards) {
      expect(c.loading).toBe(false);
      expect(c.error).toBe(false);
      expect(c.items.length).toBeGreaterThan(0);
    }
    expect(scope.cardDetails.malware.threatCard.items[0].title).toBe("DNS.PTR.Records.Scan");
    expect(scope.industryOptions).toEqual(["Healthcare"]); // "None" is junk
    scope.$destroy();
  });
});

describe("a failed request", () => {
  test("marks the card as an error (never silent no-data) and retry recovers it", async () => {
    const scope = await boot(null, true); // every op fails; the service retries each once, still fails
    const cards = allCards(scope);
    for (const c of cards) {
      expect(c.loading).toBe(false);
      expect(c.error).toBe(true);
      expect(c.items).toEqual([]);
      expect(typeof c.retry).toBe("function");
    }
    // The transport was hit twice per card call: the fresh-meta retry.
    const afterBootCalls = runAction.mock.calls.length;
    expect(afterBootCalls).toBeGreaterThan(6);

    failing = null; // the blip is over
    scope.cardDetails.malware.threatCard.retry();
    await flush(scope);
    const card = scope.cardDetails.malware.threatCard;
    expect(card.error).toBe(false);
    expect(card.items.length).toBeGreaterThan(0);
    expect(card.items[0].title).toBe("DNS.PTR.Records.Scan");
    // The other cards stay in the error state until their own retry.
    expect(scope.cardDetails.malware.countriesCard.error).toBe(true);
    scope.$destroy();
  });

  test("an empty result is NOT an error: the no-data state stays honest", async () => {
    const scope = await boot(null, null, new Set(["top_threat_industries"]));
    expect(scope.cardDetails.malware.industriesCard.error).toBe(false);
    expect(scope.cardDetails.malware.industriesCard.items).toEqual([]);
    scope.$destroy();
  });
});
