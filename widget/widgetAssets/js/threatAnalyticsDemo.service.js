'use strict';

(function () {
  angular
    .module('cybersponse')
    .factory('threatAnalyticsDemoService', threatAnalyticsDemoService);

  threatAnalyticsDemoService.$inject = ['API', 'toaster', '$resource', 'connectorService', '$q'];

  function threatAnalyticsDemoService(API, toaster, $resource, connectorService, $q) {
    var CONNECTOR = 'fortinet-fortiguard-threat-intelligence';
    var connectorMeta = null;

    // One metadata lookup per page, not one per card.
    function _meta() {
      if (!connectorMeta) {
        connectorMeta = $resource(API.INTEGRATIONS + 'connectors/?name=' + CONNECTOR).get().$promise.then(function (res) {
          var entry = res.data && res.data[0];
          var defaults = entry ? (entry.configuration || []).filter(function (c) { return c.default; }) : [];
          if (!entry || !defaults.length) {
            toaster.error({ body: 'FortiGuard Threat Intelligence: no default configuration.' });
            return $q.reject('no default configuration');
          }
          return { version: entry.version, configId: defaults[0].config_id };
        });
        connectorMeta.catch(function () { connectorMeta = null; });
      }
      return connectorMeta;
    }

    function execute(operation, params) {
      function call(m) {
        return connectorService.executeConnectorAction(CONNECTOR, m.version, operation, m.configId, params);
      }
      // One fresh-meta retry: a connector re-import mid-session or a few
      // seconds of FortiGuard cloud trouble must not blank cards until the
      // analyst reloads the page. The retry also absorbs transient 5xx/400s.
      return _meta().then(call).catch(function () {
        connectorMeta = null;
        return _meta().then(call);
      });
    }

    // Stats rows of a FortiGuard stats response, or [].
    function stats(res) {
      return (res && res.data && res.data[0] && res.data[0].Stats) || [];
    }

    // Feed timestamp of a stats response ("2026-11-06 13:29", UTC), or null.
    function logtime(res) {
      return (res && res.data && res.data[0] && res.data[0].Logtime) || null;
    }

    return { execute: execute, stats: stats, logtime: logtime };
  }
})();
