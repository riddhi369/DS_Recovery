define([
    'app/splunk_app_aws/js/libs/underscore',
    'app/splunk_app_aws/js/libs/jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/tableview',
    'app/utils/BillingUtil',
    'app/utils/BillingCurUtil',
    'app/splunk_app_aws/js/swc-aws/index',
    'app/views/dashboard/common',
    'splunkjs/mvc/simplexml/ready!'
], function (_, $, mvc, TableView, BillingUtil, BillingCurUtil, index) {
    'use strict';
    const WARNING_COLOR = '#f7ecd0';
    const EXPIRED_DAYS = 30;
    const moment = index.moment;
    const splunkd_utils = index.splunkd_utils;
    const utils = index.utils;
    //Intially both panel RI Utilization for DBR and CUR are hidden
    $("#Panel_RI_Utilization").hide();
    $("#Panel_RI_Utilization_CUR").hide();

    var billing_type_url = splunkd_utils.fullpath("saas-aws/splunk_app_aws_billing_report_type", {
        app: utils.getPageInfo().app,
        sharing: "app"
        });
    var billing_type;
    
    let enableTooltip = function ($td, placement, content) {
        $td.css('background-color', WARNING_COLOR);
        $td.attr({
            'data-toggle': 'tooltip',
            'data-placement': placement,
            'data-html': 'true',
            'data-original-title': content
        });
        $td.tooltip({container: 'body'});
    };

    let RIPlanCellRender = TableView.BaseCellRenderer.extend({
        canRender: function (cell) {
            return (cell.field === 'Expire' || cell.field === 'Scope');
        },
        render: function ($td, cell) {
            var value = cell.value;
            if (cell.field === 'Expire') {
                if (!_.isEmpty(value)) {
                    let endTime = moment(value);
                    let curTime = moment();
                    let diffDays = Math.round(endTime.diff(curTime, 'hours') / 24.0);
                    if (diffDays <= EXPIRED_DAYS) {
                        enableTooltip($td, 'left', 'Current RI will be expired within 30 days.');
                    }
                    $td.html(endTime.format('YYYY-MM-DD'));
                } else {
                    $td.html('');
                }
            } else {
                if (value !== 'Region') {
                    enableTooltip($td, 'right', 'Change the scope of the reservation from Availability Zone to Region to apply regional benefit if you don\'t require a capacity guarantee.');
                }
                $td.html(value);
            }
        }
    });

    let RIUtilizationCellRender = TableView.BaseCellRenderer.extend({
        canRender: function (cell) {
            return (cell.field === 'RI Hours Purchased' || cell.field === 'RI Hours Used' || cell.field === 'RI Utilization');
        },
        render: function ($td, cell) {
            if (cell.value === 'N/A') {
                enableTooltip($td, 'left', 'It requires detailed billing input to calculate utilization.');
            }
            $td.html(cell.value);
        }
    });

    let RIPlansTable = mvc.Components.get('RI_Plans');
    RIPlansTable.getVisualization(function (tableView) {
        tableView.addCellRenderer(new RIPlanCellRender());
    });

    let RIUtilizationTable = mvc.Components.get('RI_Utilization');
    RIUtilizationTable.getVisualization(function (tableView) {
        tableView.addCellRenderer(new RIUtilizationCellRender());
    });

    let RIUtilizationTableCur = mvc.Components.get("RI_Utilization_CUR");
    RIUtilizationTableCur.getVisualization(function(tableView) {
        tableView.addCellRenderer(new RIUtilizationCellRender)
    });

    let lastMonth = moment().add(-1, 'M').startOf('month');
    let curMonth = moment().startOf('month');

    // Display the panel based on Billing Report type selection from the configuration page
    $.get(billing_type_url + "?output_mode=json").done(function(data) {
        billing_type = data.entry[0].content.billing_type;
            
        if(billing_type == "Billing_CUR")
        {
            $("#Panel_RI_Utilization_CUR").show();
            BillingCurUtil.updateMonthSpl(BillingCurUtil.getUTCUnix(lastMonth), BillingCurUtil.getUTCUnix(curMonth), 'instance_hour_cur.', true);
        }
        else
        {
            $("#Panel_RI_Utilization").show();
            BillingUtil.updateMonthSpl(BillingUtil.getUTCUnix(lastMonth), BillingUtil.getUTCUnix(curMonth), 'aws_billing_detail_report', 'instance_hour.', true);
        }
    });	
    
});
