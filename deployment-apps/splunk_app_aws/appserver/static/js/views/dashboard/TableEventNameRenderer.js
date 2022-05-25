// To use:
//   * Add cell.eventName option to simplexml.
//   * <option name="cell.eventName">Event Name</option>
define([
    'app/splunk_app_aws/js/libs/underscore',
    'splunkjs/mvc',
    'app/splunk_app_aws/js/swc-aws/index',
    'splunkjs/mvc/tableview',
    'app/utils/SearchUtil',
    'app/splunk_app_aws/js/libs/jquery',
    'splunkjs/mvc/simplexml/ready!'
], function(_, mvc, index, TableView, SearchUtil) {
    'use strict';

    const utils = index.utils;
    const FIELDS = ['Event Name'];

    var TableEventNameRenderer = TableView.BaseCellRenderer.extend({
        initialize(options) {
            var self = this;
            this.valueMap = null;
            this.search = SearchUtil.search('| inputlookup all_eventName').then(function(lookupData) {
                var valueMap = {};

                _(lookupData).each(function(entry) {
                    valueMap[entry.eventName] = entry.highlight;
                });

                self.valueMap = valueMap;
            });
            this.fields = FIELDS;
            TableView.BaseCellRenderer.prototype.initialize.apply(this, arguments);
        },
        canRender(cell) {
            return this.fields.indexOf(cell.field) > -1;
        },
        render($td, cell) {
            var self = this;
            $.when(this.search).done(function() {
                $td.text(cell.value);
                var highlight = self.valueMap[cell.value];
                if (highlight !== null) {
                    $td.addClass('range-' + highlight);
                }
            });

            return this;
        }
    });

    return TableEventNameRenderer;
});
