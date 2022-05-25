define([
    'app/splunk_app_aws/js/libs/jquery',
    'app/libs/jquery-ui',
    'app/views/topology/TopologyView',
    'app/views/topology/panels/TimePicker',
    'app/views/dashboard/TokenHelper',
    'appcss/pages/topology/bootstrap.pcss',
    'app/views/dashboard/common',
    'splunkjs/mvc/simplexml/ready!'
], function ($, UI, TopologyView, TimePicker, TokenHelper) {

    // Create and Render
    let timePicker = new TimePicker({ el: $('#timerange'), managerid: 'timeRangeSearch'});
    $("#timepicker").change(function(event){
        timePicker.pickerChanged(event)
    });
    new TopologyView({ managerid: 'topologySearch', el: $('#aws-topology')}).render();

    TokenHelper.createLocalStorageToken('localVpc', 'form.vpc', (value) => value ? value : TokenForwarder.NO_CHANGE);

    TokenHelper.resetTokenValue('accountId', 'form.vpc', '*');
    TokenHelper.resetTokenValue('region', 'form.vpc', '*');
});
