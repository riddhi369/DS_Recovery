define([
    'app/splunk_app_aws/js/libs/jquery-ui',
    'splunkjs/mvc',
    'app/models/RIPlannerModelCur',
    'app/views/insights/RI_planner/RIPlannerFiltersView',
    'app/views/insights/table/TableView',
    'app/views/insights/RI_planner/RIPlannerControllerCur',
    'app/views/insights/RI_planner/RIPlannerConfigCur',
    'app/utils/BillingCurUtil',
    'app/splunk_app_aws/js/swc-aws/index',
    'appcss/pages/insights/RI_planner.pcss',
    'app/libs/bootstrap.tab',
    'app/views/dashboard/common',
    'splunkjs/mvc/simplexml/ready!'
], function (ui, mvc, RIPlannerModelCur, RIPlannerFiltersView, TableView, RIPlannerControllerCur, Config, BillingCurUtil, index) {
    'use strict';
    const SUBMIT_BUTTON = '.form-submit > button';
    const moment = index.moment;
    let lastMonth = moment().add(-1, 'M').startOf('month');
    let curMonth = moment().startOf('month');
    const tokenModel = mvc.Components.getInstance("default");
    const account_sm = mvc.Components.getInstance("search1");

    BillingCurUtil.updateMonthSpl(BillingCurUtil.getUTCUnix(lastMonth), BillingCurUtil.getUTCUnix(curMonth), 'instance_hour_cur.', true);

    let model = new RIPlannerModelCur();
    new RIPlannerFiltersView({
        model: model
    });
    let tableView = new TableView({
        el: $('#container'),
        model: model,
        Config: Config.TABLE
    }).render();
    let controller = new RIPlannerControllerCur(model);

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