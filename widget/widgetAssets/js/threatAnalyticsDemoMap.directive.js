'use strict';

/*
 * <threat-analytics-demo-map> -- world choropleth of event counts per country.
 *   values:   { ISO2: count }
 *   countries: { ISO2: {map, name, filter} }   (widgetAssets/lib/iso2_countries.json)
 *   base-path: widget base path (for the topojson world file)
 *   on-pick:  called with {code: ISO2} when a country is clicked
 *   palette:  'malware' | 'exploit'
 *   selected: ISO2 to outline and zoom to (others dimmed), or null
 * Uses the platform's global d3 (v5) and the bundled topojson client.
 */
(function () {
  angular
    .module('cybersponse')
    .directive('threatAnalyticsDemoMap', threatAnalyticsDemoMap);

  threatAnalyticsDemoMap.$inject = ['$q', '$timeout'];

  var worldCache = {};

  function loadScript(url) {
    return new Promise(function (resolve) {
      if (window.topojson) { resolve(); return; }
      var saved = window.define; window.define = undefined;
      var s = document.createElement('script');
      s.src = url;
      s.onload = s.onerror = function () { window.define = saved; resolve(); };
      document.head.appendChild(s);
    });
  }

  function threatAnalyticsDemoMap($q, $timeout) {
    return {
      restrict: 'E',
      scope: { values: '<', countries: '<', basePath: '<', palette: '<', selected: '<', onPick: '&' },
      template: '<div class="tad-map"><svg class="tad-map-svg"></svg>' +
        '<div class="tad-map-tip" data-ng-show="tip" data-ng-style="tipStyle">' +
        '<strong>{{tip.name}}</strong><span>{{tip.value}}</span></div>' +
        '<div class="tad-map-legend"><span>Fewer</span><i></i><span>More</span></div></div>',
      link: function (scope, el) {
        var svg = d3.select(el[0].querySelector('svg'));
        var g = svg.append('g').attr('class', 'tad-map-g');
        var holder = el[0].querySelector('.tad-map');
        var world = null;
        var byMapName = {};

        function abbreviate(n) {
          var a = Math.abs(n);
          if (a >= 1e9) { return (n / 1e9).toFixed(1) + 'B'; }
          if (a >= 1e6) { return (n / 1e6).toFixed(1) + 'M'; }
          if (a >= 1e3) { return (n / 1e3).toFixed(1) + 'K'; }
          return String(n);
        }

        function ramp() {
          return scope.palette === 'exploit'
            ? ['#1f3b4d', '#2a7f9e', '#f2b134', '#ef5a3c']
            : ['#1f3b4d', '#3e7f6f', '#e8a33d', '#d93a49'];
        }

        function draw() {
          if (!world || !scope.countries) { return; }
          byMapName = {};
          Object.keys(scope.countries).forEach(function (code) {
            var c = scope.countries[code];
            if (c.map) { byMapName[c.map] = code; }
          });
          var width = holder.clientWidth || 600;
          var height = Math.max(140, (holder.clientHeight || 300) - 14);
          svg.attr('width', width).attr('height', height);
          var features = topojson.feature(world, world.objects.countries).features
            .filter(function (f) { return f.properties.name !== 'Antarctica'; });
          // Mercator without Antarctica is close to square, so it fills the panel;
          // Natural Earth is 2:1 and left most of a tall panel empty.
          var projection = d3.geoMercator().fitExtent([[4, 4], [width - 4, height - 4]], { type: 'FeatureCollection', features: features });
          var path = d3.geoPath(projection);
          var values = scope.values || {};
          var counts = Object.keys(values).map(function (k) { return values[k]; }).filter(function (v) { return v > 0; });
          var lo = counts.length ? Math.max(1, d3.min(counts)) : 1;
          var hi = counts.length ? d3.max(counts) : 10;
          var colors = ramp();
          var t = d3.scaleLog().domain([lo, hi]).range([0, 1]).clamp(true);
          var color = d3.scaleLinear().domain([0, 0.4, 0.75, 1]).range(colors).interpolate(d3.interpolateRgb);

          var sel = g.selectAll('path.tad-country').data(features, function (f) { return f.properties.name; });
          sel.enter().append('path').attr('class', 'tad-country')
            .on('mousemove', function (f) {
              var code = byMapName[f.properties.name];
              var v = code ? (scope.values || {})[code] : null;
              var box = holder.getBoundingClientRect();
              // d3.event is gone by the time $applyAsync runs: read it now.
              var x = d3.event.clientX - box.left + 12;
              var y = d3.event.clientY - box.top + 12;
              scope.$applyAsync(function () {
                scope.tip = { name: (code && scope.countries[code].name) || f.properties.name, value: v ? abbreviate(v) + ' events' : 'no data' };
                scope.tipStyle = { left: x + 'px', top: y + 'px' };
              });
            })
            .on('mouseleave', function () { scope.$applyAsync(function () { scope.tip = null; }); })
            .on('click', function (f) {
              var code = byMapName[f.properties.name];
              if (code && (scope.values || {})[code]) { scope.$applyAsync(function () { scope.onPick({ code: code }); }); }
            })
            .merge(sel)
            .attr('d', path)
            .classed('has-data', function (f) { var c = byMapName[f.properties.name]; return !!(c && values[c]); })
            .transition().duration(600)
            .style('fill', function (f) {
              var code = byMapName[f.properties.name];
              var v = code ? values[code] : 0;
              return v ? color(t(v)) : null;
            });
          focus(path, features, width, height);
          el[0].querySelector('.tad-map-legend i').style.background =
            'linear-gradient(90deg,' + colors.join(',') + ')';
        }

        // Outline + zoom to the selected country; reset when none.
        function focus(path, features, width, height) {
          var code = scope.selected;
          var name = code && scope.countries && scope.countries[code] ? scope.countries[code].map : null;
          var target = name ? features.filter(function (f) { return f.properties.name === name; })[0] : null;
          g.selectAll('path.tad-country')
            .classed('is-selected', function (f) { return !!target && f === target; })
            .classed('is-dimmed', function (f) { return !!target && f !== target; });
          var k = 1;
          var tx = 0;
          var ty = 0;
          if (target) {
            var b = path.bounds(target);
            var dx = b[1][0] - b[0][0];
            var dy = b[1][1] - b[0][1];
            k = Math.max(1, Math.min(5, 0.55 / Math.max(dx / width, dy / height)));
            tx = width / 2 - k * (b[0][0] + dx / 2);
            ty = height / 2 - k * (b[0][1] + dy / 2);
            g.selectAll('path.is-selected').raise();
          }
          g.transition('zoom').duration(750)
            .attr('transform', 'translate(' + tx + ',' + ty + ') scale(' + k + ')')
            .selectAll('path').style('stroke-width', (0.5 / k) + 'px');
        }

        var url = scope.basePath + 'widgetAssets/lib/countries-110m.json';
        $q.all([loadScript(scope.basePath + 'widgetAssets/lib/topojson-client.min.js'),
          worldCache[url] || (worldCache[url] = d3.json(url))]).then(function (r) {
          world = r[1];
          $timeout(draw);
        });

        scope.$watchGroup(['values', 'countries', 'palette', 'selected'], function () { draw(); });
        var onResize = function () { draw(); };
        window.addEventListener('resize', onResize);
        scope.$on('$destroy', function () { window.removeEventListener('resize', onResize); });
      }
    };
  }
})();
