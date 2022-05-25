define([
    'app/splunk_app_aws/js/libs/jquery',
    'app/splunk_app_aws/js/libs/underscore',
    'app/splunk_app_aws/js/libs/backbone',
    'splunkjs/mvc',
    'app/splunk_app_aws/js/swc-aws/index',
    'contrib/text!app/views/insights/templates/RI_planner/RIBasisTooltipTemplate.html',
    'app/views/insights/RI_planner/RIPlannerConfig'
], function ($, _, Backbone, mvc, index, BasisTooltipTemplate, Config) {
    const BaseView = index.BaseView;
    const ControlGroup = index.ControlGroup;
    return BaseView.extend({
        initialize: function () {
            BaseView.prototype.initialize.apply(this, arguments);
            this.tokens = mvc.Components.get('default');
            // control filters' model
            this.stateModel = new Backbone.Model();
            this.stateModel.set('base', this.tokens.get('base'));
            this.stateModel.set('payment', this.tokens.get('payment'));
            this.stateModel.on('change:base', (() => {
                this.tokens.set('base', this.stateModel.get('base'));
            }).bind(this));
            this.stateModel.on('change:payment', (() => {
                this.tokens.set('payment', this.stateModel.get('payment'));
            }).bind(this));
        },

        enableFilters: function () {
            this.baseRadio.enable();
            this.paymentRadio.enable();
        },

        disableFilters: function () {
            this.baseRadio.disable();
            this.paymentRadio.disable();
        },

        render: function () {
            this.$el.html('<div id="base-input" class="filter-input"></div><div id="payment-input" class="filter-input"></div>');
            this.baseRadio = new ControlGroup({
                el: $('#base-input'),
                label: 'Basis for insight',
                controlType: 'SyntheticRadio',
                controlOptions: {
                    model: this.stateModel,
                    modelAttribute: 'base',
                    items: Config.FILTERS.BASE_OPTIONS
                }
            });
            this.$el.append(this.baseRadio.render().$el);
            // tooltip for basis
            this.$('#base-input .control-label').append(' ' + BasisTooltipTemplate);
            this.$('[data-toggle="tooltip"]').tooltip({container: '#headerContainer'});

            this.paymentRadio = new ControlGroup({
                el: $('#payment-input'),
                label: 'Payment option(one-year term)',
                controlType: 'SyntheticRadio',
                controlOptions: {
                    model: this.stateModel,
                    modelAttribute: 'payment',
                    items: Config.FILTERS.PAYMENT_OPTIONS
                }
            });
            this.$el.append(this.paymentRadio.render().$el);
            this.disableFilters();
        }
    });
});
