/**
 * Created by hshen on 10/8/16.
 */
define([
    'app/splunk_app_aws/js/libs/jquery',
    'app/splunk_app_aws/js/libs/underscore',
    'app/splunk_app_aws/js/libs/backbone',
    'app/splunk_app_aws/js/swc-aws/index',
    'contrib/text!app/views/silvermine_insights/templates/Header.html'
],function($, _, Backbone, index, Header){
    const BaseView = index.BaseView;
    return BaseView.extend({
        className: 'silvermine-header',

        initialize: function(params){
            BaseView.prototype.initialize.apply(this, arguments);
        },

        render:function(){
            this.$el.html(this.template);

            return this;
        },

        template: Header
    })
});