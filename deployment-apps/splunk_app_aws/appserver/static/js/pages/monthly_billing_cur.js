define([
    'app/splunk_app_aws/js/libs/underscore',
    'splunkjs/mvc',
    'app/views/dashboard/OneTimePaymentsView',
    'app/splunk_app_aws/js/swc-aws/index',
    'app/views/dashboard/MonthSelectorCur',
    'app/views/dashboard/DataModelChecker',
    'app/views/dashboard/common',
    'splunkjs/mvc/simplexml/ready!'
], function(_, mvc, OneTimePaymentsView, index, MonthSelectorCur, DataModelChecker) {

    let tokenModel = mvc.Components.getInstance("default");
    let submitModel = mvc.Components.getInstance('submitted');
    //to check whether the datamodel has been built or is currently building.
    DataModelChecker.check('Detailed_Billing_CUR');
    DataModelChecker.check('Instance_Hour_CUR');
    
    tokenModel.set("billingAccountId","(LinkedAccountId=\"*\")");
    tokenModel.set("ih_billingAccountId",'(instance_hour_cur.LinkedAccountId="*")');
    tokenModel.on("change:dm_billingAccountId", function(billingAccountId, dm_billingAccountId) {
       var billingAccountId=dm_billingAccountId.replace(/detailed_billing_cur./g,""); 
       var ih_billingAccountId=dm_billingAccountId.replace(/detailed_billing_cur./g,"instance_hour_cur.");
        tokenModel.set("billingAccountId",billingAccountId);
        tokenModel.set("ih_billingAccountId",ih_billingAccountId);
    });

    new MonthSelectorCur({
        from: $('#timerange-from'),
        fromTitle: 'Billing report from',
        to: $('#timerange-to'),
        submit: true,
        fromCurrentMonth: false,
        isDetailedBilling: false
    }).render();

    tokenModel.set('onetimeDetailedBilling', '');
    if (tokenModel && submitModel) {
        submitModel.set(tokenModel.toJSON());
    }

    let oneTimePaymentsView = new OneTimePaymentsView({
        default: true,
        el: $('#oneTime')
    }).render();

    let mgr = mvc.Components.getInstance('baseSearch');

    mgr.on('search:start', () => {
        oneTimePaymentsView.loading(true);
    });

    mgr.on('search:done', () => {
        oneTimePaymentsView.loading(false);
    });

    oneTimePaymentsView.on('change', (include) => {
        lazyRefreshInvoice(include);
    });

    let lazyRefreshInvoice = _.debounce((include) => {
        tokenModel.set('onetimeDetailedBilling', include ? '' : 'count > 2');
        if (tokenModel && submitModel) {
            submitModel.set(tokenModel.toJSON());
        }
    }, 200);
    
});