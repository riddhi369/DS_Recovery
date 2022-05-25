define([
    'app/splunk_app_aws/js/libs/underscore',
    'splunkjs/mvc',
    'app/views/dashboard/DataModelChecker',
    'app/views/dashboard/common',
    'splunkjs/mvc/simplexml/ready!'
], function(_, mvc, DataModelChecker) {
    DataModelChecker.check('Instance_Hour_CUR');
});