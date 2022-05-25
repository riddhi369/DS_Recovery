/**
 * Created by peter on 6/5/15.
 */
define(
    [
        'app/splunk_app_aws/js/libs/jquery_configure',
        'app/splunk_app_aws/js/libs/underscore',
        'app/splunk_app_aws/js/libs/backbone_configure',
        'app/splunk_app_aws/js/swc-aws/configure_index',
        'app/views/configuration/billing/Manager',
        'app/views/configuration/warning_message/Manager',
        'app/views/common/BaseSection',
        'app/configure/Config',
        '@splunk/ui-utils/i18n'
    ],
    function (
        $,
        _,
        Backbone,
        index,
        BillingTagView,
        WarningMessageView,
        BaseSection,
        Config,
        ui
    ) {
        'use strict';
        const BaseModel = index.BaseModel;
        const BaseView = index.BaseView;

        return BaseView.extend({
            initialize: function (options) {
                BaseView.prototype.initialize.apply(this, arguments);

                this.children.messageSettingView = new WarningMessageView();
                this.children.billingTagView = new BillingTagView();

                this.children.billingSection = new BaseSection({
                    className: 'billing-setting-section',
                    label: ui.gettext('Billing')
                });

                this.children.billingSection.renderContent = ($content) => {
                    $content.append(this.children.billingTagView.render().el);
                };

                this.children.baseSection = new BaseSection({
                    className: 'other-setting-section'
                });

                this.children.baseSection.renderContent = ($content) => {
                    $content.append(this.children.messageSettingView.render().el);
                };

            },

            render: function () {
                // do not show "edit billing tags" button when the user is not aws admin
                if (Config.contextData.IS_AWS_ADMIN) {
                    this.$el.append(this.children.billingSection.render().el);
                }
                this.$el.append(this.children.baseSection.render().el);

                return this;
            }

        });
    });
