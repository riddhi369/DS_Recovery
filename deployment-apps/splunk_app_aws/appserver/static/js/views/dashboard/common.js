define([
    'app/splunk_app_aws/js/libs/underscore',
    'splunkjs/mvc',
    'app/splunk_app_aws/js/swc-aws/index',
    'app/views/dashboard/SimpleWarningHelper',
    'app/views/dashboard/CustomIndexHelper',
//    'app/views/dashboard/LiteHelper',
    'app/views/dashboard/SourcetypeCheckerView',
    'app/views/dashboard/TagInputView',
    'app/views/dashboard/TableBarRenderer',
    'app/views/dashboard/TableEventNameRenderer',
    'app/views/dashboard/TableCellRenderer',
    'app/views/dashboard/SingleValueRenderer',
    'app/views/dashboard/TokenHelper',
    'app/views/dashboard/MacroHelper',
    'app/views/dashboard/RestrictedSearchTermHelper',
    'splunkjs/mvc/tokenforwarder',
    'app/models/Config',
    'app/utils/SearchUtil',
    'app/collections/Recommendations',
    'app/views/anomaly_detection/views/InfoView',
    'app/views/dashboard/MultiSelectHelper',
    'appcss/dashboards/common.pcss',
    'splunkjs/mvc/simplexml/ready!'
], function(
    _,
    mvc,
    index,
    SimpleWarningHelper,
    CustomIndexHelper,
//    LiteHelper,
    SourcetypeCheckerView,
    TagInputView,
    TableBarRenderer,
    TableEventNameRenderer,
    TableCellRenderer,
    SingleValueRenderer,
    TokenHelper,
    MacroHelper,
    RestrictedSearchTermHelper,
    TokenForwarder,
    Config,
    SearchUtil,
    Recommendations,
    InfoView
){
    'use strict';
    
    const utils = index.utils;
    const splunkd_utils = index.splunkd_utils;
    // check the value in KV store lookup and if the value does not exist then run the custom command reload the page to have updated navigation	
    SearchUtil.search('|inputlookup instance_type', {
        'earliest_time': '-1d'
    }).then((resultData) => {
        if (resultData.length == 0) {
            SearchUtil.search('|checkinstancetype', {
                'earliest_time': '-1d'
            }).then((resultData) => {
                if (resultData.length > 0) {
                    location.reload()
                }
            }, function(err) {
                console.log(err);
            });
        }
    }, function(err) {
        console.log(err);
    });
    TokenHelper.createLocalStorageToken('localAccountId', 'form.accountId', (accounts) => accounts ? accounts.split(',') : TokenForwarder.NO_CHANGE);
    TokenHelper.createLocalStorageToken('localRegions', 'form.region', (regions) => regions ? regions.split(',') : TokenForwarder.NO_CHANGE);
    let _tokenModel = mvc.Components.get('default');
    // set token for restricted search term
    RestrictedSearchTermHelper.setRestrictedSearchTermToken();

    let page = utils.getPageInfo().page,
        app = utils.getPageInfo().app;

    var service = mvc.createService();
    var confs = service.configurations({
        owner: "nobody",
        app: "splunk_app_aws"
    });

    // render a info message regarding steps to upgrade AWS App
    confs.fetch(function (err, confs) 
    {
        var conf = confs.item("app");
        conf.fetch(function (err, apps) 
        {
            var properties = apps.properties();
            for (var i = 0; i < properties.entry.length; i++)
            {
                var stanza_name = properties.entry[i].name;
                if(stanza_name == "upgrade")
                {
                    var status = properties.entry[i].content["status"];
                    if (status == "0")
                    {
                        let info = new InfoView;
                        info.render_info_view();
                        info.showUpgradeInfo();
                    }
                }
            }
        });
    });

    // render simple warning
    SimpleWarningHelper.showWarning();

    // set tag input view
    let $tags = $('#awstags');
    if ($tags.length > 0 ) {
        new TagInputView({
            'el': $tags
        }).render();
        let tags = _tokenModel.get('tags');
        if (!tags) {
            _tokenModel.set('tags', '');
        }
    }

    // set common renders
    Object.keys(mvc.Components.attributes).forEach((componentName) => {
        let component = mvc.Components.get(componentName);

        if (typeof component.getVisualizationType !== 'undefined') {
            let vizType = component.getVisualizationType();

            if (vizType === 'table' || vizType === 'statistics') {
                // bar renderer
                component.getVisualization(function (tableView) {
                    tableView.table.addCellRenderer(new TableBarRenderer());
                    tableView.table.render();
                });

                // event name renderer
                component.getVisualization(function (tableView) {
                    tableView.table.addCellRenderer(new TableEventNameRenderer());
                    tableView.table.render();
                });

                // table cell renderer
                component.getVisualization(function (tableView) {
                    tableView.table.addCellRenderer(new TableCellRenderer());
                    tableView.table.render();
                });
            } else if (vizType === 'single' || vizType === 'visualizations:singlevalue') {
                // single value renderer
                component.getVisualization(function (single) {
                    let $el = $('<div></div>').insertAfter(single.$el);
                    new SingleValueRenderer($.extend(single.settings.toJSON(), {
                        el: $el,
                        id: _.uniqueId('single')
                    }));
                });
            }
        }
    });

    // load config context data, check and show warnings
    Config.loadContext().done(function () {
        // track usage information

        let url = splunkd_utils.fullpath('saas-aws/splunk_app_aws_warning_message', {
            app: app,
            sharing: 'app'
        });

        let callbackFunc = function () {
            // check sourcetype
            new SourcetypeCheckerView();

            // check custom indexes
            CustomIndexHelper.checkCustomIndex(Config.contextData.IS_AWS_ADMIN);
        };

        // if user hides messages of this page, will not do sourcetype check
        $.get(`${url}?output_mode=json`).done((data) => {
            let pages = data.entry[0].content.pages;

            if (pages.indexOf(page) === -1) {
                callbackFunc();
            }
        }).fail(() => {
            callbackFunc();
        });

    });

    // disable insights for lite
    //    LiteHelper.disableInsights();

    // check ML lib
    let recommendations = new Recommendations();

    recommendations.fetch({data: {count: -1}}).done(() => {
        let submittedTokenModel = mvc.Components.getInstance("submitted");

        // set this token, so that some panels relying on it can show up.
        submittedTokenModel.set('recommendationEnabled', true);
    });

});
