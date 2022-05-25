define([
    'app/splunk_app_aws/js/libs/jquery',
    'app/splunk_app_aws/js/libs/underscore',
    'app/splunk_app_aws/js/libs/backbone',
    'app/splunk_app_aws/js/swc-aws/index',
    'app/models/Config'
], function ($, _, Backbone, index, Config) {
    
    const BaseView = index.BaseView;

    var WaitingPanel = BaseView.extend({

        className: 'custom-waiting-panel',

        initialize: function() {
            BaseView.prototype.initialize.apply(this, arguments);
        },

        render: function() {
            var template = this.compiledTemplate({
                    message: this.message
                });
            this.$el.html(template);
            return this;
        },

        /**
         * show message upon the modal backdrop
         * @param message the text to be rendered. Show 'Please wait ...' in case not defined.
         */
        show: function(message) {
            if ($('.custom-waiting-panel').length === 0) {
                $('body').append(this.render().el);
            }

            this.$el.html(this.compiledTemplate({
                message: message || 'Please wait ...'
            }));

            this.$el.removeClass('hide');
        },

        close: function() {
            this.$el.addClass('hide');
        },

        template: '\
            <div class="modal-backdrop model-white"></div>\
            <div class="msg">\
                <img class="img" src="../../../static/app/' + Config.contextData.APP + '/img/loading.gif" />\
                <span class="text"><%= message %></span></div>\
            '
    });

    var waitingPanel = new WaitingPanel();

    return waitingPanel;
});
