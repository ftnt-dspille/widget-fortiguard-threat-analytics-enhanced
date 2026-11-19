"use strict";
// Unit test for the analytics demo connector service: the metadata lookup is
// cached (N calls make ONE lookup), a failed lookup is retried by the next
// call, and a FAILED CALL is retried once with freshly fetched metadata so a
// connector re-import mid-session or a few seconds of FortiGuard cloud trouble
// does not blank cards until the analyst reloads.
//
//   make test-unit WIDGET=fortiGuardThreatAnalyticsDemo

global.jasmine = global.jasmine || {};
require("angular");
require("angular-mocks");

angular.module("cybersponse", []); // eslint-disable-line no-undef
require("../widget/widgetAssets/js/threatAnalyticsDemo.service.js");

const ngModule = window.angular.mock.module; // eslint-disable-line no-undef
const ngInject = window.angular.mock.inject; // eslint-disable-line no-undef

let resourceGets; // the $resource("...connectors/?name=...") metadata GETs
let toasts;
let runAction;

beforeEach(() => {
  jest.spyOn(console, "error").mockImplementation(() => {});
  toasts = [];
  runAction = jest.fn();
  resourceGets = jest.fn();
  ngModule("cybersponse", ($provide) => {
    $provide.value("API", { INTEGRATIONS: "/api/integration/" });
    $provide.value("toaster", { error: (t) => toasts.push(t.body) });
    $provide.value("connectorService", { executeConnectorAction: (...a) => runAction(...a) });
    $provide.value("$resource", () => ({ get: () => ({ $promise: resourceGets() }) }));
  });
});
afterEach(() => jest.restoreAllMocks());

const META = ($q) => $q.resolve({
  data: [{ version: "4.2.0", configuration: [{ config_id: "c9", default: true }] }],
});

function run(setLookup, cb) {
  ngInject(["threatAnalyticsDemoService", "$rootScope", "$q", (svc, $rs, $q) => {
    resourceGets.mockImplementation(() => setLookup($q));
    let err = null;
    let val = null;
    svc.execute("act", { a: 1 }).then((v) => { val = v; }, (e) => { err = e; });
    // The fresh-meta retry deepens the chain: each $q stage advances one
    // digest, so digest well past the retry before asserting.
    for (let i = 0; i < 12; i++) { $rs.$digest(); }
    cb(err, val, svc, $rs);
  }]);
}

test("default configuration -> runs the action with its id, no toast", () => {
  run(($q) => {
    runAction.mockReturnValue($q.resolve({ data: [] }));
    return $q.resolve({ data: [{ version: "4.2.0", configuration: [{ config_id: "c9", default: true }] }] });
  }, (err, val) => {
    expect(err).toBeNull();
    expect(runAction).toHaveBeenCalledWith("fortinet-fortiguard-threat-intelligence", "4.2.0", "act", "c9", { a: 1 });
    expect(toasts).toHaveLength(0);
  });
});

test("no default configuration -> readable error once", () => {
  run(($q) => $q.resolve({ data: [{ version: "4.2.0", configuration: [{ config_id: "c1", default: false }] }] }), (err) => {
    expect(err).toBe("no default configuration");
  });
});

test("two calls -> one metadata lookup (cached), both run", () => {
  run(($q) => {
    runAction.mockReturnValue($q.resolve({ data: [] }));
    return $q.resolve({ data: [{ version: "4.2.0", configuration: [{ config_id: "c9", default: true }] }] });
  }, (err, val, svc, $rs) => {
    expect(err).toBeNull();
    svc.execute("a", {}).catch(() => {});
    svc.execute("b", {}).catch(() => {});
    $rs.$digest();
    expect(resourceGets).toHaveBeenCalledTimes(1);
    expect(runAction).toHaveBeenCalledTimes(3); // 1 from run() + 2 here
  });
});

test("a failed metadata lookup is retried in place, and the next call looks up again", () => {
  let fail = true;
  run(($q) => (fail ? $q.reject("down") : META($q)), (err, val, svc) => {
    expect(err).toBe("down");
    fail = false;
    svc.execute("a", {}).catch(() => {});
    // 2 lookups for the failed call (its in-place fresh-meta retry) + 1 here.
    expect(resourceGets).toHaveBeenCalledTimes(3);
  });
});

test("a failed call is retried once with fresh metadata and succeeds", () => {
  let fail = true;
  run(($q) => {
    runAction.mockImplementation(() => {
      const first = fail;
      fail = false; // only the first attempt fails; the fresh-meta retry succeeds
      return first ? $q.reject({ data: { message: "KeyError: 0" } }) : $q.resolve({ data: [{ Logtime: "L", Stats: [] }] });
    });
    return META($q);
  }, (err, val, svc, $rs) => {
    expect(err).toBeNull();
    expect(val).toEqual({ data: [{ Logtime: "L", Stats: [] }] });
    // The service-level retry recovered the call: meta was fetched twice and
    // the action ran twice for this one execute().
    expect(resourceGets).toHaveBeenCalledTimes(2);
    expect(runAction).toHaveBeenCalledTimes(2);
  });
});

test("a persistently failing call makes exactly two attempts, then throws", () => {
  run(($q) => {
    runAction.mockReturnValue($q.reject({ data: { message: "down" } }));
    return META($q);
  }, (err) => {
    expect(err).toEqual({ data: { message: "down" } });
    expect(resourceGets).toHaveBeenCalledTimes(2);
    expect(runAction).toHaveBeenCalledTimes(2);
  });
});

test("stats() and logtime() read the feed envelope", () => {
  ngInject(["threatAnalyticsDemoService", (svc) => {
    const res = { data: [{ Logtime: "2026-11-19 00:44", Stats: [{ Count: 5, Name: "x" }] }] };
    expect(svc.stats(res)).toEqual([{ Count: 5, Name: "x" }]);
    expect(svc.logtime(res)).toBe("2026-11-19 00:44");
    expect(svc.stats(null)).toEqual([]);
    expect(svc.stats({ data: [] })).toEqual([]);
    expect(svc.logtime({ data: [{}] })).toBeNull();
  }]);
});
