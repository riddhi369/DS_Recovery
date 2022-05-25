/**
 * Created by peter on 6/5/15.
 */
define(['app/splunk_app_aws/js/swc-aws/configure_index'], function(index) {
    const BaseView = index.BaseView;

    return BaseView.extend({
        initialize: function () {
            BaseView.prototype.initialize.apply(this, arguments);
        },

        render: function () {
            this.$el.html(this.template);
            return this;
        },

        template: '\
            <div class="aws-page-header">\
                <div class="title">Configure</div>\
            </div>\
            '
    });
});






