/**
 * Created by hshen on 10/5/16.
 */
define([
    'app/splunk_app_aws/js/libs/jquery',
    'app/splunk_app_aws/js/libs/underscore',
    'splunkjs/mvc',
    'app/splunk_app_aws/js/libs/backbone',
    'app/views/silvermine_insights/SilvermineView',
    'app/splunk_app_aws/js/swc-aws/index',
    '@splunk/ui-utils/i18n',
    'appcss/pages/silvermine_insights/bootstrap.pcss',
    'app/views/dashboard/common',
    'splunkjs/mvc/simplexml/ready!'
], function($, _, mvc, Backbone, SilvermineView, index, ui) {
    'use strict';

    const ControlGroup = index.ControlGroup;
    let model = new Backbone.Model({
        serviceType: '*',  // Show all by default
        showedDates: [],     // Dates to show in the table
        allDates: []        // All dates for search results
    });

    let serviceTypeRadio =  new ControlGroup({
        el: $('#service-type-input'),
        label: ui.gettext("Service Status"),
            controlType: 'SyntheticRadio',
            controlOptions: {
                model: model,
                modelAttribute: 'serviceType',
                items: [{label: 'All',value: '*'}, {label: 'Problematic Only',value: 'problematic'}]
            }
        }).render().el;

    $(serviceTypeRadio).parent().parent()
        .css('display', 'inline-block')
        .css('margin-right', '10px')
        .css('vertical-align', 'top');

    // Create and Render
    new SilvermineView({ 
        managerid: 'silvermineSearch', 
        el: $('#silvermine-container'),
        model: model
    }).render();

});
