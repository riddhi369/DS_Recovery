/**
 * Created by frank on 2016/08/30.
 */

define([
    'app/splunk_app_aws/js/libs/jquery_configure',
    'app/splunk_app_aws/js/libs/underscore',
    'app/splunk_app_aws/js/libs/backbone_configure',
	'app/splunk_app_aws/js/swc-aws/configure_index',
    'contrib/text!app/views/configuration/warning_message/template.html',
], function($, _, Backbone, index, template){
	const SearchManager=index.SearchManager;
    const utils=index.utils;
    const splunkd_utils = index.splunkd_utils;
    var url=splunkd_utils.fullpath('saas-aws/splunk_app_aws_warning_message', {
        app: utils.getPageInfo().app,
        sharing: 'app'
    });
	var url2 = splunkd_utils.fullpath('saas-aws/splunk_app_aws_billing_report_type', {
        app: utils.getPageInfo().app,
		sharing: 'app'
	});

    return Backbone.View.extend({
        tagName: 'div',

        className: 'message-setting-view',

        events: {
            'click .message-setting-check': '_submitChecks',
			'click .billing-choose-check': '_submitChecks2'
        },

        constructor: function (options) {
            Backbone.View.apply(this, arguments);
        },

        render: function() {
            this.$el.html(template);
            this._getChecks();
            return this;
        },

        _getChecks: function() {
            // if user hides messages of this page, will not do sourcetype check
            $.get(`${url}?output_mode=json`).done((data) => {
                var page_roots = data.entry[0].content.page_roots;

                this.$el.find('.message-setting-check').prop('checked', true);

                page_roots.forEach((page_root) => {
                    this.$el.find(`.message-setting-check[value=${page_root}]`).prop('checked', false);
                });

                this.$el.find('.message-setting-check').removeAttr('disabled');
            });
			$.get(url2 + "?output_mode=json").done((data) => {
				var billing_type = data.entry[0].content.billing_type;
				var CURCheck = new SearchManager({
					earliest_time: "0",
					latest_time: "now",
					search: "`aws-billing-sourcetype-cur` | fields _raw | head 1"
				});
				if (billing_type[0] !== undefined){
					this.$el.find('.billing-choose-check').removeAttr('disabled');
					/* checking the radio button for billing type that is selected */
					if (billing_type[0] == "Billing")  
						this.$el.find(`.billing-choose-check[value=${billing_type[0]}]`).prop('checked', !0);
					else{
						this.$el.find(`.billing-choose-check[value=${billing_type[0]}]`).prop('checked', !0);
						CURCheck.startSearch();
						CURCheck.on("search:done", function(state, job) {
							if (state.content.resultCount === 0){
								$('#bill-error').text('Please configure Billing (Cost and Usage Report) input in the Add-on.');
							}
						});
					}
				}
				else {
					/* statements for being undefined, that is when the app is installed the first time */
					var billing_type = [];
					billing_type.push("Billing");
					$.ajax({
						url: url2 + "?output_mode=json",
						type: "post",
						dataType: "json",
						data: {
							name: "update_billing_type",
							billing_type: billing_type.join(",")
                        },
						success: function () {
							$(".billing-choose-check").removeAttr("disabled");
							$(".billing-choose-check[value='Billing']").prop("checked", !0);
                        }
                    });
				}
			});
        },
        _submitChecks: function() {
            var page_roots = [];
            this.$el.find('.message-setting-check:not(:checked)').each(function() {
                page_roots.push($(this).val());
            });
            $.ajax({
                url: `${url}?output_mode=json`,
                type: 'post',
                dataType: 'json',
                data: {
                    name: 'update_message_settings',
                    page_roots: page_roots.join(',')
                }
            });
        }
		,_submitChecks2: function() {
			var billing_type = [];
			this.$el.find(".billing-choose-check:checked").each(function() {
				billing_type.push($(this).val())
			});
			var CURCheck = new SearchManager({
				earliest_time: "0",
				latest_time: "now",
				search: "`aws-billing-sourcetype-cur` | fields _raw | head 1"
			});
			if (billing_type[0] == "Billing_CUR"){
				CURCheck.startSearch();
				CURCheck.on("search:done", function(state, job) {
					if (state.content.resultCount === 0){
						$('#bill-error').text('Please configure Billing (Cost and Usage Report) input in the Add-on.');
					}
				});
			}
			$.ajax({
				url: url2 + "?output_mode=json",
				type: "post",
				dataType: "json",
				data: {
					name: "update_billing_type",
					billing_type: billing_type.join(",")
				},
				success: function() {
					window.setTimeout(location.reload(), 2500)
				}
			});
        }
    });
});