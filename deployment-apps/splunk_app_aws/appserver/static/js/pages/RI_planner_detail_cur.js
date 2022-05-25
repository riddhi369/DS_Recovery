define([
    'app/splunk_app_aws/js/libs/jquery-ui',
    'app/splunk_app_aws/js/libs/underscore',
    'splunkjs/mvc',
    'app/models/RIPlannerDetailModelCur',
    'app/views/insights/RI_planner/RIPlannerDetailDataBuilderCur',
    'app/views/insights/RI_planner/RIPlannerDetailHeaderView',
    'app/views/insights/RI_planner/RIPlannerDetailSingleViewCur',
    'app/views/insights/RI_planner/RIPlannerDetailChartViewCur',
    'app/views/insights/RI_planner/RIPlannerConfigCur',
    'app/views/insights/RI_planner/RIPlannerHelperCur',
    'app/views/dashboard/common',
    'appcss/pages/insights/RI_planner_detail.pcss',
    'splunkjs/mvc/simplexml/ready!'
], function (ui, _, mvc, RIPlannerDetailModelCur, RIPlannerDetailDataBuilderCur, RIPlannerDetailHeadView, RIPlannerDetailSingleViewCur, RIPlannerDetailChartViewCur, Config, Helper) {
    'use strict';
    let model = new RIPlannerDetailModelCur();
    let tokens = mvc.Components.get('default');
    let defaultEarliest = tokens.get('earliest');
    let defaultLatest = tokens.get('latest');
    new RIPlannerDetailHeadView({
        el: $('#headerContainer'),
        model: model
    }).render();
    let singleView = new RIPlannerDetailSingleViewCur({
        model: model
    });
    let chartView = new RIPlannerDetailChartViewCur({
        el: `#${Config.CHART_CONTAINER_ID}`,
        model: model
    }).render();
    new RIPlannerDetailDataBuilderCur(model, defaultEarliest, defaultLatest);

    // filter base change, single view will re-calculate
    tokens.on('change:base', (()=> {
        model.changeSingleData(tokens.get('base'));
    }));
    // filter payment change, single view will re-calculate
    tokens.on('change:payment', singleView.formatData.bind(singleView));
    // chart reset
    chartView.on(Config.EVENT.RESET, (()=> {
        tokens.set('earliest', defaultEarliest);
        tokens.set('latest', defaultLatest);
        model.changeSingleData(tokens.get('base'));
    }));
    // chart drag
    chartView.on(Config.EVENT.DRAG_POINT, model.dragPointToModifySingleData.bind(model));
    $(`#${Config.CHART_CONTAINER_ID}`).on(Config.EVENT.SELECT_TIME, (event, start, end) => {
        // ri single view drilldown
        let startDayIndex = Helper.timeToIndex(start),
            endDayIndex = Helper.timeToIndex(end),
            startDayTime = Helper.start.getTime() + startDayIndex * Config.ONE_DAY_MIS,
            endDayTime = Helper.start.getTime() + (endDayIndex + 1) * Config.ONE_DAY_MIS - 1;
        tokens.set('earliest', startDayTime * Config.TIMESTAMP_TO_SPLUNK_TIME_COEF);
        tokens.set('latest', endDayTime * Config.TIMESTAMP_TO_SPLUNK_TIME_COEF);
        model.selectTimeToModifySingleData(startDayIndex, endDayIndex);
    });
});
