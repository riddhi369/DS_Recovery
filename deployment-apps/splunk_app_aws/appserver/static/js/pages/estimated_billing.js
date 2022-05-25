define([
    'app/splunk_app_aws/js/libs/jquery',
    'app/splunk_app_aws/js/libs/underscore',
    'app/splunk_app_aws/js/libs/backbone',
    'splunkjs/mvc',
    'app/utils/LookupUtil',
    'app/views/dashboard/common',
    'splunkjs/mvc/simplexml/ready!'
], function ($, _, Backbone, mvc, LookupUtil) {
    LookupUtil.generateAccountName();
});
