/**
 * Created by michael on 6/21/15.
 */

define([
    'app/splunk_app_aws/js/libs/jquery_configure',
    'app/splunk_app_aws/js/libs/underscore',
    'app/splunk_app_aws/js/libs/backbone_configure',
    'app/splunk_app_aws/js/swc-aws/configure_index'
], function($, _, Backbone, index) {
    
    const BaseView = index.BaseView;
    var MSG_TYPE_ERROR = 'MSG_TYPE_ERROR';
    var MSG_TYPE_WARNING = 'MSG_TYPE_WARNING';

    //TODO, a close handler and a markdown renderer
    return BaseView.extend({

        initialize: function () {
            BaseView.prototype.initialize.apply(this, arguments);
            //TODO
            //this.desc = this.options.desc; //md syntax
        },

        /**
         * show message in the header of the dialog
         * @param msg: can be a object with property msg and type or just a message string
         * @param type MSG_TYPE_ERROR or MSG_TYPE_WARNING. can be null if it is contained in msg object
         * @private
         */
        showMsg: function (msg, type) {
            //if (this.timeoutId != null) {
            //    clearTimeout(this.timeoutId);
            //}
            //
            if (typeof msg === 'string') {
                msg = {type: type || MSG_TYPE_ERROR, msg: msg};
            }

            if (msg.type !== MSG_TYPE_WARNING && msg.type !== MSG_TYPE_ERROR) {
                return;
            }

            this.content = msg.msg;
            this.type = msg.type;

            this.render();

            // remove it after 10 seconds
            //this.timeoutId = setTimeout(function() {
            //    this.timeoutId = null;
            //    this._hide();
            //}.bind(this), 10000);
        },

        showError: function (msg) {
            return this.showMsg(msg, MSG_TYPE_ERROR);
        },

        showWarning: function (msg) {
            return this.showMsg(msg, MSG_TYPE_WARNING);
        },

        render: function () {
            var template = this.compiledTemplate({
                    msgClass: this.type ? (this.type === MSG_TYPE_WARNING ? 'msg-warning' : 'msg-error') : 'msg-none',
                    iconClass: this.type === MSG_TYPE_WARNING ? 'icon-warning-sign' : 'icon-alert-circle'
                }
            );
            this.$el.html(template);
            this.$('.msg-text').html(this.content);

            this.$el.show();

            return this;
        },

        events: {
            'click .close': 'hide'
        },

        hide: function () {
            this.$el.hide();
        },

        template: '\
            <div class="msg <%= msgClass %>">\
                <button type="button" class="close">×</button>\
                <i class="icon <%= iconClass %>"></i>\
                <div class="msg-text">\
                </div>\
            </div>'
    });
});