/**
 * Created by frank on 2016-09-05
 */

define(['app/splunk_app_aws/js/libs/backbone'], function(Backbone){
    return Backbone.Model.extend({
        defaults: {
            events: null,
            warningMessage: null,
            loading: false
        }
    });
});