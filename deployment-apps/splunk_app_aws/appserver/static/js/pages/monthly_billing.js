define([
    'app/splunk_app_aws/js/libs/underscore',
    'splunkjs/mvc',
    'app/views/dashboard/OneTimePaymentsView',
    'app/utils/LookupUtil',
    'app/splunk_app_aws/js/swc-aws/index',
    'app/views/dashboard/MonthSelector',
    'app/views/dashboard/common',
    'splunkjs/mvc/simplexml/ready!'
], function(_, mvc, OneTimePaymentsView, LookupUtil, index, MonthSelector) {


    let tokenModel = mvc.Components.getInstance("default");
    let submitModel = mvc.Components.getInstance('submitted');

    new MonthSelector({
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

    LookupUtil.generateAccountName();
});