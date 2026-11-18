'use strict';

/*
 * tad-fit-rows="card": sets card.fit to how many rows of `row-height` px fit
 * in this element (at least 3), and keeps it current on resize. The card then
 * shows that many items instead of stretching a fixed five.
 */
(function () {
  angular
    .module('cybersponse')
    .directive('tadFitRows', tadFitRows);

  tadFitRows.$inject = ['$timeout'];

  function tadFitRows($timeout) {
    return {
      restrict: 'A',
      link: function (scope, el, attrs) {
        var rowHeight = parseInt(attrs.rowHeight, 10) || 38;
        function measure() {
          var card = scope.$eval(attrs.tadFitRows);
          var h = el[0].clientHeight;
          if (!card || !h) { return; }
          var fit = Math.max(3, Math.floor(h / rowHeight));
          if (card.fit !== fit) { scope.$applyAsync(function () { card.fit = fit; }); }
        }
        $timeout(measure);
        var ro = window.ResizeObserver ? new ResizeObserver(measure) : null;
        if (ro) { ro.observe(el[0]); } else { window.addEventListener('resize', measure); }
        scope.$on('$destroy', function () {
          if (ro) { ro.disconnect(); } else { window.removeEventListener('resize', measure); }
        });
      }
    };
  }
})();
