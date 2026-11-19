/* Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end */
'use strict';
(function () {
    angular
        .module('cybersponse')
        .controller('editFortiGuardThreatAnalyticsDemo101DevCtrl', editFortiGuardThreatAnalyticsDemo101DevCtrl);

    editFortiGuardThreatAnalyticsDemo101DevCtrl.$inject = ['$scope', '$uibModalInstance', 'config', 'threatAnalyticsDemoUtilityService', '$timeout'];

    function editFortiGuardThreatAnalyticsDemo101DevCtrl($scope, $uibModalInstance, config, threatAnalyticsDemoUtilityService, $timeout) {
        $scope.cancel = cancel;
        $scope.save = save;
        $scope.SORT_ORDER = [{
          value: 'asc',
          label: 'Ascending'
        }, {
          value: 'desc',
          label: 'Descending'
        }];
        $scope.intervalOptions = {
          'Last 1 Day': 1,
          'Last 3 Days': 3,
          'Last 7 Days': 7,
          'Last 14 Days': 14,
          'Last 21 Days': 21
        };
        $scope.threatTypeOptions = [
          { value: 'virus', label: 'Virus' },
          { value: 'ips', label: 'IPs' }
        ];
        let defaultConfig = {
          threat_type: 'virus',
          order: 'desc',
          time_windows: 14,
          max_records: 5
        };

        $scope.config = config;
        $scope.config.threat_type = $scope.config.threat_type || defaultConfig.threat_type;
        $scope.config.order = $scope.config.order || defaultConfig.order;
        $scope.config.time_windows = $scope.config.time_windows || defaultConfig.time_windows;
        $scope.config.max_records = $scope.config.max_records || defaultConfig.max_records;

        function _handleTranslations() {
          let widgetNameVersion = threatAnalyticsDemoUtilityService.getWidgetNameVersion($scope.$resolve.widget, $scope.$resolve.widgetBasePath);
          if (widgetNameVersion) {
            threatAnalyticsDemoUtilityService.checkTranslationMode(widgetNameVersion).then(function () {
              $scope.viewWidgetVars = {
                // Create your translating static string variables here]
                BTN_OK: threatAnalyticsDemoUtilityService.translate('threatAnalytics.BTN_OK'),
                HEADER_EDIT_THREAT_ANALYTICS: threatAnalyticsDemoUtilityService.translate('threatAnalytics.HEADER_EDIT_THREAT_ANALYTICS'),
                INTERVALS: threatAnalyticsDemoUtilityService.translate('threatAnalytics.INTERVALS'),
                LABEL_NOT_CONFIGURABLE: threatAnalyticsDemoUtilityService.translate('threatAnalytics.LABEL_NOT_CONFIGURABLE'),
                NUMBER_OF_RECORDS: threatAnalyticsDemoUtilityService.translate('threatAnalytics.NUMBER_OF_RECORDS'),
              };
            });
          }
          else {
            $timeout(function () {
              cancel();
            }, 100)
          }
        }

        function init() {
            _handleTranslations();
        }

        init();

        function cancel() {
            $uibModalInstance.dismiss('cancel');
        }

        function save() {
            $uibModalInstance.close($scope.config);
        }

    }
})();
