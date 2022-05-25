define([
    'app/splunk_app_aws/js/libs/underscore',
    'app/splunk_app_aws/js/libs/jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/checkboxview',
    'contrib/text!app/views/dashboard/OneTimePaymentsTemplate.html'
], function(_, $, mvc, CheckboxView, OneTimePaymentsTemplate) {
    'use strict';

    const TITLE = 'Include Onetime Payments';
    const LOADING = 'Loading...';

    var OneTimePaymentsView = CheckboxView.extend({

        initialize() {
            CheckboxView.prototype.initialize.apply(this, arguments);
        },

        loading(loading) {
            if (loading) {
                this.$el.find('span').text(LOADING);
                this.settings.set('disabled', true);
            } else {
                this.$el.find('span').text(TITLE);
                this.settings.set('disabled', false);
            }
        },

        render() {
            let view = CheckboxView.prototype.render.apply(this, arguments);

            view.$el.parent().parent()
                .css('display', 'inline-block')
                .css('margin-left', '10px')
                .css('min-width', '180px')
                .css("vertical-align","top")
                .css("margin-top","24px");
            view.$el.find('[data-component="splunk-core:/splunkjs/mvc/components/Checkbox"]')
                .css('display','inline-block');
            view.$el.find('input').css('margin-top', '0');
            var anchor=document.getElementById("fieldset1").getElementsByTagName("a");
            if(anchor && anchor.length>0)
            {
                anchor[0].style.verticalAlign="top";
            }
            
            if (view.$el.find('span').length === 1) {
                view.$el.append(`<span style="margin-left: 5px;">${TITLE}</span> `);
                view.$el.append(OneTimePaymentsTemplate);

                view.$('[data-toggle="tooltip"]').tooltip();
            }

            return view;
        }
    });

    return OneTimePaymentsView;
});
