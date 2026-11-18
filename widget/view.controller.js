'use strict';

/*
 * FortiGuard Threat Analytics (Demo) -- fork of FortiGuard Threat Analytics 1.0.0.
 * Headline numbers with sparklines and a trend against the 21-day daily
 * average, a country heat map that filters (and focuses on) a country, ranked
 * cards drawn by the widget itself (the original needs the `utilities`
 * widget), and a threat drill-down panel.
 */
(function () {
  angular
    .module('cybersponse')
    .controller('fortiGuardThreatAnalyticsDemo100DevCtrl', fortiGuardThreatAnalyticsDemo100DevCtrl);

  fortiGuardThreatAnalyticsDemo100DevCtrl.$inject = ['$scope', '$rootScope', '$q', '$http', '$interval', 'config',
    'widgetBasePath', 'threatAnalyticsDemoService', 'threatAnalyticsDemoUtilityService'];

  function fortiGuardThreatAnalyticsDemo100DevCtrl($scope, $rootScope, $q, $http, $interval, config,
    widgetBasePath, svc, utility) {
    // The feed only answers these windows (others fail), and totals do not
    // scale with the window, so trends compare daily rates, never sums.
    var WINDOWS = [1, 3, 7, 14, 21];
    var BASELINE = 21;
    // Placeholder labels the feed uses for "no industry recorded".
    var JUNK_LABELS = /^(empty|none|unknown|n\/a|-|)$/i;
    var TYPES = {
      malware: { threatType: 'Malware', statsType: 'Malware Distribution Activity' },
      exploit: { threatType: 'Vulnerability', statsType: 'Intrusion Prevention Activity' }
    };

    $scope.theme = $rootScope.theme.id;
    $scope.config = config;
    $scope.basePath = widgetBasePath;
    $scope.widgetCSS = widgetBasePath + 'widgetAssets/css/fortiGuardThreatAnalyticsDemo.css';
    $scope.dateRanges = { 'Last 1 Day': 1, 'Last 3 Days': 3, 'Last 7 Days': 7, 'Last 14 Days': 14, 'Last 21 Days': 21 };
    $scope.filters = { dateRange: _window(config.time_windows || 7), industry: null, country: null };
    $scope.countryOptions = [];
    $scope.industryOptions = [];
    $scope.showClearFilter = false;
    $scope.mapView = 'malware';
    $scope.mapValues = { malware: {}, exploit: {} };
    $scope.mapTop = [];
    $scope.selectedCode = null;
    $scope.kpis = [];
    $scope.overviewLoading = false;
    $scope.asOf = null;
    $scope.drill = null;
    $scope.abbreviate = abbreviate;
    $scope.shareLabel = shareLabel;
    $scope.applyFilters = applyFilters;
    $scope.clearFilters = clearFilters;
    $scope.pickCountry = pickCountry;
    $scope.openThreat = openThreat;
    $scope.closeThreat = function () { $scope.drill = null; };
    $scope.setMapView = function (v) { $scope.mapView = v; mapTop(); };
    $scope.severity = severity;

    function _window(n) {
      n = parseInt(n, 10);
      return WINDOWS.indexOf(n) >= 0 ? n : 7;
    }

    var regionNames = null;
    try { regionNames = new Intl.DisplayNames(['en'], { type: 'region' }); } catch (e) { regionNames = null; }

    // Country name for an ISO2 code: our table first, then the browser's own list.
    function countryName(code) {
      if ($scope.countries && $scope.countries[code]) { return $scope.countries[code].name; }
      try { return (regionNames && /^[A-Z]{2}$/.test(code) && regionNames.of(code)) || code; } catch (e) { return code; }
    }

    function abbreviate(n) {
      if (n === null || n === undefined || isNaN(n)) { return '-'; }
      var a = Math.abs(n);
      if (a >= 1e12) { return (n / 1e12).toFixed(1) + 'T'; }
      if (a >= 1e9) { return (n / 1e9).toFixed(1) + 'B'; }
      if (a >= 1e6) { return (n / 1e6).toFixed(1) + 'M'; }
      if (a >= 1e3) { return (n / 1e3).toFixed(1) + 'K'; }
      return String(Math.round(n));
    }

    function shareLabel(share) {
      if (share > 0 && share < 0.1) { return '<0.1%'; }
      return (Math.round(share * 10) / 10) + '%';
    }

    // A rough severity from the signature name, for the bar colour only.
    function severity(title) {
      var t = String(title || '');
      if (/exploit|rce|remote\.code|overflow|injection|traversal|backdoor|ransom|cve/i.test(t)) { return 'critical'; }
      if (/scan|recon|probe|brute|suspicious/i.test(t)) { return 'medium'; }
      return 'high';
    }

    function noteAsOf(res) {
      var t = svc.logtime(res);
      if (t && (!$scope.asOf || t > $scope.asOf)) { $scope.asOf = t; }
    }

    // ------------------------------------------------------------ cards
    function createCard(title, subtitle, kind) {
      return { title: title, subtitle: subtitle, kind: kind, items: [], loading: false };
    }

    function createSection(title, key) {
      return {
        key: key,
        title: title,
        threatCard: createCard('Top Threats', 'Most prevalent signatures in the period', 'threat'),
        countriesCard: createCard('Top Targeted Countries', 'Most attacked countries in the period', 'country'),
        industriesCard: createCard('Top Targeted Industries', 'Most attacked industries in the period', 'industry')
      };
    }

    $scope.cardDetails = {
      vulnerabilities: createSection('Exploits', 'exploit'),
      malware: createSection('Malware', 'malware')
    };

    function toItems(stats, labelKey) {
      var rows = stats.filter(function (s) {
        return !((labelKey === 'Industry' || labelKey === 'Country') && JUNK_LABELS.test(String(s[labelKey] || '')));
      });
      var max = rows.reduce(function (m, s) { return Math.max(m, s.Count || 0); }, 0) || 1;
      var total = rows.reduce(function (m, s) { return m + (s.Count || 0); }, 0) || 1;
      return rows.map(function (s, i) {
        var label = s[labelKey];
        if (labelKey === 'Country') { label = countryName(label); }
        return {
          rank: i + 1,
          title: label,
          code: labelKey === 'Country' ? s.Country : null,
          id: s.ID,
          threattype: s.Threattype,
          value: s.Count,
          pct: Math.round((s.Count / max) * 100),
          share: (s.Count / total) * 100
        };
      });
    }

    function loadCard(action, params, card, labelKey) {
      card.loading = true;
      // Ask for extra rows so placeholder industries can be dropped and still fill the card.
      var want = 10;
      var p = angular.extend({}, params, { max_records: labelKey === 'Industry' || labelKey === 'Country' ? want + 3 : want });
      return svc.execute(action, p).then(function (res) {
        noteAsOf(res);
        card.items = toItems(svc.stats(res), labelKey).slice(0, want);
      }).catch(function (err) {
        console.error('threat analytics demo: card', action, err);
        card.items = [];
      }).finally(function () {
        card.loading = false;
      });
    }

    function loadSection(section, threatType) {
      var params = {
        threat_type: threatType,
        order: config.order === 'asc' ? 'Ascending' : 'Descending',
        time_windows: $scope.filters.dateRange,
        max_records: config.max_records || 5
      };
      loadCard('top_threats', params, section.threatCard, 'Name');
      loadCard('top_threat_countries', params, section.countriesCard, 'Country');
      loadCard('top_threat_industries', params, section.industriesCard, 'Industry');
    }

    function codeForFilter(name) {
      if (!name || !$scope.countries) { return null; }
      return Object.keys($scope.countries).filter(function (c) { return $scope.countries[c].filter === name; })[0] || null;
    }

    // Same operations as the original widget's filters.
    function applyFilters() {
      var f = $scope.filters;
      f.dateRange = _window(f.dateRange);
      $scope.selectedCode = codeForFilter(f.country);
      $scope.drill = null;
      loadOverview();
      if (!f.country && !f.industry) {
        $scope.showClearFilter = false;
        loadSection($scope.cardDetails.malware, 'Malware');
        loadSection($scope.cardDetails.vulnerabilities, 'Vulnerability');
        return;
      }
      $scope.showClearFilter = true;
      var base = {
        order: config.order === 'asc' ? 'Ascending' : 'Descending',
        time_windows: f.dateRange,
        max_records: config.max_records || 5,
        country: f.country || null,
        industry: f.industry || null
      };
      var sections = [
        { type: TYPES.malware, cards: $scope.cardDetails.malware },
        { type: TYPES.exploit, cards: $scope.cardDetails.vulnerabilities }
      ];
      sections.forEach(function (s) {
        var threat = angular.extend({}, base, { threat_type: s.type.threatType });
        var activity = angular.extend({}, base, { threat_type: s.type.statsType });
        if (f.country && f.industry) {
          loadCard('top_threats_country_industry', threat, s.cards.threatCard, 'Name');
          loadCard('threat_activities_statistics_by_country_and_industry', activity, s.cards.countriesCard, 'Country');
          loadCard('threat_activities_statistics_by_country_and_industry', activity, s.cards.industriesCard, 'Industry');
        } else if (f.country) {
          loadCard('top_threats_by_country', threat, s.cards.threatCard, 'Name');
          loadCard('threat_activities_statistics_by_country', activity, s.cards.countriesCard, 'Country');
          loadCard('top_industries_country', threat, s.cards.industriesCard, 'Industry');
        } else {
          loadCard('top_threats_by_industry', threat, s.cards.threatCard, 'Name');
          loadCard('top_countries_industry', threat, s.cards.countriesCard, 'Country');
          loadCard('threat_activities_statistics_by_industry', activity, s.cards.industriesCard, 'Industry');
        }
      });
    }

    function clearFilters() {
      $scope.filters.country = null;
      $scope.filters.industry = null;
      applyFilters();
    }

    function pickCountry(code) {
      var c = $scope.countries && $scope.countries[code];
      if (!c || !c.filter) { return; }
      $scope.filters.country = c.filter;
      applyFilters();
    }

    // ------------------------------------------------------------ overview
    // One request per (type, window) for the page's life: filters re-use them.
    var totalsCache = {};
    function countryTotals(threatType, windowDays) {
      var key = threatType + ':' + windowDays;
      if (!totalsCache[key]) {
        totalsCache[key] = svc.execute('top_threat_countries', {
          threat_type: threatType, order: 'Descending', time_windows: windowDays, max_records: 200
        }).then(function (res) { noteAsOf(res); return svc.stats(res); })
          .catch(function () { delete totalsCache[key]; return null; });
      }
      return totalsCache[key];
    }

    function sum(stats) {
      return (stats || []).reduce(function (m, s) { return m + (s.Count || 0); }, 0);
    }

    function trend(cur, curDays, base, baseDays) {
      if (!cur || !base) { return null; }
      var baseRate = base / baseDays;
      return baseRate ? Math.round(((cur / curDays) / baseRate - 1) * 100) : null;
    }

    // Sparkline over the windows, longest first, so the line reads old -> recent.
    function spark(byWindow, perDay) {
      var wins = WINDOWS.slice().reverse();
      var vals = wins.map(function (w) {
        var v = byWindow[w];
        return v === null || v === undefined ? null : (perDay ? v / w : v);
      });
      var known = vals.filter(function (v) { return v !== null; });
      if (known.length < 2) { return null; }
      var lo = Math.min.apply(null, known);
      var hi = Math.max.apply(null, known);
      var W = 120;
      var H = 32;
      var pts = [];
      vals.forEach(function (v, i) {
        if (v === null) { return; }
        var x = (i / (vals.length - 1)) * W;
        var y = hi === lo ? H / 2 : H - 3 - ((v - lo) / (hi - lo)) * (H - 6);
        pts.push(x.toFixed(1) + ',' + y.toFixed(1));
      });
      return {
        line: pts.join(' '),
        area: '0,' + H + ' ' + pts.join(' ') + ' ' + W + ',' + H,
        last: pts[pts.length - 1].split(','),
        labels: wins.map(function (w) { return w + 'd'; })
      };
    }

    var tweens = [];
    function countUp(kpi) {
      var start = Date.now();
      var target = kpi.value || 0;
      kpi.shown = 0;
      var t = $interval(function () {
        var p = Math.min(1, (Date.now() - start) / 900);
        kpi.shown = target * (1 - Math.pow(1 - p, 3));
        if (p >= 1) { $interval.cancel(t); }
      }, 30);
      tweens.push(t);
    }

    function mapTop() {
      var vals = $scope.mapValues[$scope.mapView] || {};
      $scope.mapTop = Object.keys(vals).sort(function (a, b) { return vals[b] - vals[a]; }).slice(0, 5).map(function (c) {
        return { code: c, name: countryName(c), value: vals[c] };
      });
    }

    var overviewSeq = 0;
    function loadOverview() {
      var seq = ++overviewSeq;
      var w = $scope.filters.dateRange;
      var bw = w === BASELINE ? 14 : BASELINE;
      $scope.overviewLoading = true;
      var calls = { topThreat: svc.execute('top_threats', {
        threat_type: 'Vulnerability', order: 'Descending', time_windows: w, max_records: 1
      }).then(svc.stats).catch(function () { return []; }) };
      WINDOWS.forEach(function (win) {
        calls['m' + win] = countryTotals('Malware', win);
        calls['e' + win] = countryTotals('Vulnerability', win);
      });
      $q.all(calls).then(function (r) {
        if (seq !== overviewSeq) { return; }
        var values = { malware: {}, exploit: {} };
        (r['m' + w] || []).forEach(function (s) { if (!JUNK_LABELS.test(String(s.Country || ''))) { values.malware[s.Country] = s.Count; } });
        (r['e' + w] || []).forEach(function (s) { if (!JUNK_LABELS.test(String(s.Country || ''))) { values.exploit[s.Country] = s.Count; } });
        $scope.mapValues = values;
        mapTop();

        var combined = {};
        ['malware', 'exploit'].forEach(function (k) {
          Object.keys(values[k]).forEach(function (c) { combined[c] = (combined[c] || 0) + values[k][c]; });
        });
        var top = Object.keys(combined).sort(function (a, b) { return combined[b] - combined[a]; })[0];
        var topName = top ? countryName(top) : null;
        var trendLabel = 'vs ' + bw + '-day daily avg';

        var mByW = {};
        var eByW = {};
        var cByW = {};
        WINDOWS.forEach(function (win) {
          var m = r['m' + win];
          var e = r['e' + win];
          mByW[win] = m ? sum(m) : null;
          eByW[win] = e ? sum(e) : null;
          if (m || e) {
            var set = {};
            (m || []).concat(e || []).forEach(function (s) { if (!JUNK_LABELS.test(String(s.Country || ''))) { set[s.Country] = true; } });
            cByW[win] = Object.keys(set).length;
          }
        });

        $scope.kpis = [
          { key: 'malware', label: 'Malware events', icon: 'fa-bug', value: mByW[w],
            trend: trend(mByW[w], w, mByW[bw], bw), trendLabel: trendLabel, spark: spark(mByW, true),
            sparkTitle: 'Daily malware events, averaged over 21, 14, 7, 3 and 1 days' },
          { key: 'exploit', label: 'Exploit attempts', icon: 'fa-crosshairs', value: eByW[w],
            trend: trend(eByW[w], w, eByW[bw], bw), trendLabel: trendLabel, spark: spark(eByW, true),
            sparkTitle: 'Daily exploit attempts, averaged over 21, 14, 7, 3 and 1 days' },
          { key: 'countries', label: 'Countries targeted', icon: 'fa-globe', value: cByW[w],
            plain: true, note: 'with malware or exploit activity', spark: spark(cByW, false),
            sparkTitle: 'Countries with activity in the last 21, 14, 7, 3 and 1 days' },
          { key: 'top', label: 'Most targeted', icon: 'fa-bullseye', text: topName || '-', code: top,
            note: top ? abbreviate(combined[top]) + ' events' : '',
            sub: (r.topThreat[0] && r.topThreat[0].Name) ? 'Top exploit: ' + r.topThreat[0].Name : '' }
        ];
        $scope.kpis.forEach(function (k) { if (!k.text) { countUp(k); } });
      }).finally(function () {
        if (seq === overviewSeq) { $scope.overviewLoading = false; }
      });
    }

    // ------------------------------------------------------------ drill-down
    var threatCache = {};
    function threatsFor(threatType, win) {
      var key = threatType + ':' + win;
      if (!threatCache[key]) {
        threatCache[key] = svc.execute('top_threats', {
          threat_type: threatType, order: 'Descending', time_windows: win, max_records: 50
        }).then(svc.stats).catch(function () { delete threatCache[key]; return null; });
      }
      return threatCache[key];
    }

    function encyclopediaUrl(item) {
      var kind = { virus: 'virus', ips: 'ips', botnet: 'botnet', app: 'appcontrol' }[String(item.threattype || '').toLowerCase()];
      if (kind && item.id) { return 'https://www.fortiguard.com/encyclopedia/' + kind + '/' + item.id; }
      return 'https://www.fortiguard.com/search?q=' + encodeURIComponent(item.title) + '&engine=1';
    }

    function openThreat(item, section) {
      var threatType = section.key === 'malware' ? 'Malware' : 'Vulnerability';
      var d = $scope.drill = {
        item: item,
        section: section.title,
        category: item.threattype === 'ips' ? 'IPS signature' : (item.threattype === 'virus' ? 'Antivirus signature' : (item.threattype || 'Signature')),
        severity: severity(item.title),
        url: encyclopediaUrl(item),
        window: $scope.filters.dateRange,
        scope: [$scope.filters.country, $scope.filters.industry].filter(Boolean).join(' / ') || 'worldwide',
        loading: true,
        history: [],
        spark: null
      };
      $q.all(WINDOWS.map(function (win) { return threatsFor(threatType, win); })).then(function (lists) {
        if ($scope.drill !== d) { return; }
        var byW = {};
        lists.forEach(function (list, i) {
          var win = WINDOWS[i];
          var hit = (list || []).filter(function (s) { return (item.id && s.ID === item.id) || s.Name === item.title; })[0];
          var rank = hit ? list.indexOf(hit) + 1 : null;
          byW[win] = hit ? hit.Count : null;
          d.history.push({ window: win, count: hit ? hit.Count : null, perDay: hit ? hit.Count / win : null, rank: rank });
        });
        d.spark = spark(byW, true);
      }).finally(function () { d.loading = false; });
    }

    // ------------------------------------------------------------ setup
    function loadLookups() {
      $http.get(widgetBasePath + 'widgetAssets/json/countries.json').then(function (res) {
        $scope.countryOptions = res.data.countries;
      });
      svc.execute('get_industry_list', {}).then(function (res) {
        $scope.industryOptions = ((res && res.data) || []).filter(function (i) { return !JUNK_LABELS.test(String(i)); });
      });
      return $http.get(widgetBasePath + 'widgetAssets/lib/iso2_countries.json').then(function (res) {
        $scope.countries = res.data;
      });
    }

    function translations() {
      utility.checkTranslationMode($scope.$parent.model.type).then(function () {
        $scope.viewWidgetVars = {
          APPLY_FILTER: utility.translate('threatAnalytics.APPLY_FILTER'),
          CLEAR_FILTER: utility.translate('threatAnalytics.CLEAR_FILTER'),
          COUNTRIES: utility.translate('threatAnalytics.COUNTRIES'),
          DATE_RANGE: utility.translate('threatAnalytics.DATE_RANGE'),
          INDUSTRIES: utility.translate('threatAnalytics.INDUSTRIES'),
          SELECT_AN_OPTION: utility.translate('threatAnalytics.SELECT_AN_OPTION')
        };
      });
    }

    $scope.$on('$destroy', function () { tweens.forEach(function (t) { $interval.cancel(t); }); });

    translations();
    loadLookups().finally(applyFilters);
  }
})();
