define([
    'app/splunk_app_aws/js/libs/jquery-ui',
    'splunkjs/mvc',
    'app/models/RIPlannerModel',
    'app/views/insights/RI_planner/RIPlannerFiltersView',
    'app/views/insights/table/TableView',
    'app/views/insights/RI_planner/RIPlannerController',
    'app/views/insights/RI_planner/RIPlannerConfig',
    'appcss/pages/insights/RI_planner.pcss',
    'app/libs/bootstrap.tab',
    'app/views/dashboard/common',
    'splunkjs/mvc/simplexml/ready!'
], function (ui, mvc, RIPlannerModel, RIPlannerFiltersView, TableView, RIPlannerController, Config) {
    'use strict';
    const SUBMIT_BUTTON = '.form-submit > button';
    const tokenModel = mvc.Components.getInstance("default");
    const account_sm = mvc.Components.getInstance("search1");

    let model = new RIPlannerModel();
    new RIPlannerFiltersView({
        model: model
    });
    let tableView = new TableView({
        el: $('#container'),
        model: model,
        Config: Config.TABLE
    }).render();
    let controller = new RIPlannerController(model);

    // by default, sort by yearly saving
    model.on('change:rowsReady', ()=>{
        if (model.get('rowsReady')) {
            tableView.headView.toggleSortIcon(Config.TABLE.YEARLY_SAVING_INDEX);
        }
    });
    // user submit filters
    $(`${SUBMIT_BUTTON}:not(disabled)`).click(()=> {
        // reset sort
        tableView.headView.resetSortIcons();
        // empty model rows
        model.emptyRows();
        // clear table
        tableView.bodyView.removeViews();
        // generate table results
        controller.generateResults();
    });

    function hideFilters(){
        $('#input1_all').css('display', 'none');
        $('#input2').css('display', 'none');
        $('#input3').css('display', 'none');
        $('#input2_all').css('display', 'none');
    }
    function showFilters(){
        $('#input1_all').css('display','inline-block');
        $('#input2').css('display','inline-block');
        $('#input3').css('display','inline-block');
        $('#input2_all').css('display','inline-block');
    }
    hideFilters();
    account_sm.on("search:done",function(){
        showFilters();
    });

    tokenModel.on("change:accountId",(tm)=>{
        if (!tm.get("accountId")){
            hideFilters();
        }
        else{
            showFilters();
        }
    });

});