define([
    'app/splunk_app_aws/js/libs/jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/searchmanager',
    'app/collections/Recommendations',
    'app/views/dashboard/common',
    'splunkjs/mvc/simplexml/ready!'
], function ($, mvc, SearchManager, Recommendations) {
    
    var tokenModel = mvc.Components.getInstance("default");
    var submitModel = mvc.Components.getInstance("submitted");
    let EC2recommendations = new Recommendations();
    var recommendationEnabled;
    var sm = new SearchManager({
        id: 'ec2Search',
        search: '| rest services/saas-aws/splunk_app_aws_recommendation splunk_server=local | search resource_type="i" | join resource_id [search earliest=-1d `aws-description-resource($accountId$, $region$, "ec2_instances")` | rename id as resource_id | fields resource_id]',
        preview: true

    },{tokens: true});

    EC2recommendations.fetch({data: {count: -1}}).done(() => {
        // set this token, so that some panels relying on it can show up.
        tokenModel.set('recommendationEnabled', true);
        recommendationEnabled = tokenModel.get("recommendationEnabled");
    }).then(function(){
        sm.on("search:done",function(){
            if(recommendationEnabled)
            {
                tokenModel.set("ec2InsightsResult",sm.attributes.data.resultCount);
            }
            else
            {
                tokenModel.set("ec2InsightsResult","N/A");
            }
            if (tokenModel && submitModel) {
                submitModel.set(tokenModel.toJSON());
            }
        });
    });
});