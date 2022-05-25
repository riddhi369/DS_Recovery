define([
    'app/splunk_app_aws/js/libs/underscore',
    'app/splunk_app_aws/js/libs/jquery_configure',
    'app/splunk_app_aws/js/libs/backbone_configure',
    'app/splunk_app_aws/js/swc-aws/configure_index',
    'app/configure/SearchUtil',
    'app/utils/Util',
    'app/utils/HelpLinks',
    '@splunk/ui-utils/i18n'
], (_, $, Backbone, index, SearchUtil, AppUtil, HelpLinks, ui) => {
    'use strict';
    const mvc = index.mvc;
    const SavedSearchManager = index.SavedSearchManager;
    const utils = index.utils;
    const CheckboxGroup = index.CheckboxGroup;
    const Modal = index.Modal;
    const splunkd_utils = index.splunkd_utils;

    const appName = utils.getPageInfo().app;
    const legacy_url = splunkd_utils.fullpath("saas-aws/splunk_app_aws_data_model", {
        app: appName,
        sharing: "app"
    });
    const cur_url = splunkd_utils.fullpath("saas-aws/splunk_app_aws_data_model_cur", {
        app: appName,
        sharing: "app"
    });
    var billing_type, data_model_tags, 
        warning_message = '\
            <div class="alert alert-warning"> \
                <i class="icon-alert"></i> \
                No custom tags found. Please check "Billing: Billing Reports S3Key Generator" is scheduled.\
            </div> \
        ';

    const BUTTON_SAVE = `<a href="#" id="tag-save" class="btn pull-right btn-primary">${ui.gettext('Save')}</a>`;
    const BUTTON_CANCEL = `<a href="#" id="tag-cancel" class="btn pull-left">${ui.gettext('Cancel')}</a>`;

    let TagModal = Modal.extend({
        events: {
            'click #tag-save': 'onSave',
            'click #tag-cancel': 'onCancel'
        },

        constructor: function(options) {
            options || (options = {});
            _.extend(options, {
                keyboard: false,
                backdrop: 'static'
            });
            Modal.call(this, options);
        },

        initialize: function() {
            var _that = this;
            // declaring _that to use outer scope of "this" inside jQuery.get() function
            Modal.prototype.initialize.apply(this, arguments);

            this.checkBoxTemplate = '\
                <div class="tag-key"><input type="checkbox" value="<%-tag%>" <%-checked%>/><%-tag%></div>\
            ';

            this.warningTemplate = '\
                <p>You can filter and group data in your Capacity Planner and Historical \
                Detailed Billing dashboards using your own custom tags. Select the tags \
                you would like to use on these dashboards from the list below. <b>For best \
                performance, select only the tags you need.</b></p> \
                <div class="tag-warning alert alert-warning"> \
                    <p>All changes on this screen cause your Capacity Planner and Historical \
                    Detailed Billing dashboards to be unavailable while their underlying data \
                    models are rebuilt. The time required depends on the volume of your \
                    billing data.</p> \
                    ' + AppUtil.buildLinkNode(HelpLinks.AWS_BILLING_TAGS) + ' </div>';

            if (!this.model) {
                this.model = new Backbone.Model();
            }

            this.model.set({
                'loaded': false,
                'tags': [],
                'modelTags': [],
                'state': 'Loading reports...'
            });
            var url2 = splunkd_utils.fullpath("saas-aws/splunk_app_aws_billing_report_type", {
                app: utils.getPageInfo().app,
                sharing: "app"
            });

            var reg = /user:(.*?),/g;
            var keyReg = /user:(.*?)=/;

            let searchId = _.uniqueId('tags');

            $.get(url2 + "?output_mode=json").done(function(data) {
                billing_type = data.entry[0].content.billing_type; 
                var searchString = "";
                if (billing_type[0] !== undefined && billing_type[0] == "Billing_CUR") {
                    searchString = '| inputlookup billing_report_assemblyid_cur | fields assemblyId  | map search="| search `aws-billing-sourcetype-cur-digest` source="*$assemblyId$*"" | head 1 | fields _raw';
                    reg = /user:(.*?)"/g;
                    keyReg = /user:(.*?)"/;
                    data_model_tags = '| `aws-billing-datamodel-tags-cur` | fields title | search title=*';
                    warning_message = '\
                        <div class="alert alert-warning"> \
                            <i class="icon-alert"></i> \
                            No custom tags found. Please check "Billing CUR: Billing Reports AssemblyId Generator" is scheduled.\
                        </div> \
                    ';
                }
                else {
                    searchString ='| inputlookup billing_report_s3key | search eventtype=aws_billing_detail_report | fields source| map search="| search `aws-billing-details("*")` source="$source$" | head 1 | fields _raw"';
                    data_model_tags = '| `aws-billing-datamodel-tags` | fields title | search title=*';
                }
                
                SearchUtil.search(searchString, {
                    id: searchId
                }).then((sources) => {
                    if (!sources || sources.length === 0) {
                        return;
                    }
                    sources.forEach(data => {
                        let prevTags = _that.model.get('tags') || [];
                        try {
                            let spl = data._raw;
                            let matches = spl.match(reg);
                            if (!matches) {
                                return;
                            }
                            let tags = matches.map(key => {
                                let match = key.match(keyReg);
                                if (match && match[1]) {
                                    return match[1];
                                }
                            });

                            tags = prevTags.concat(tags);
                            tags = _.uniq(tags);

                            _that.model.set('tags', tags);
                        } catch (err) {
                            console.log(err);
                            _that.model.set('tags', prevTags);
                        }
                    });
                }).always(function() {
                    _that.model.set("loaded", !0)
                });
                // Update progress
                let sm = mvc.Components.get(searchId);
                if (sm) {
                    sm.on('search:progress', (properties) => {
                        _that.model.set('state', `Loading reports... ${Math.round(properties.content.doneProgress * 100)}%`);
                    });
                }
                SearchUtil.search(data_model_tags)
                    .then((data) => {
                        if (data.length === 0) {
                            return;
                        }
                        _that.model.set('modelTags', data.map(row => row.title));
                    });
    
                    _that.listenTo(_that.model, 'change:loaded', _that.reRenderBody);
            });// end of getting billing type from end-point function
        }, // end of initialize function

        reRenderBody() {
            let tags = this.model.get('tags') || [];
            let modelTags = this.model.get('modelTags') || [];
            let $tagList = this.$(Modal.BODY_SELECTOR).find('#tag-list');

            tags = tags.concat(modelTags.filter((i) => tags.indexOf(i) === -1));

            if (!tags || tags.length === 0) {
                $tagList.html(_.template(warning_message));
                this.$el.find('#tag-save').hide();
                return;
            }

            // A potential "bug" here.
            // If the user deletes the billing data, then tags will still be popup
            // However, this is the only way for the user to unselect a tag.
            let items = tags.map(tag => {
                return {
                    label: tag,
                    value: tag
                };
            });

            if (this.children.tagsCheckbox) {
                this.children.tagsCheckbox.remove();
            }

            this.children.tagsCheckbox = new CheckboxGroup({
                model: this.model,
                modelAttribute: 'modelTags',
                items: items
            });

            $tagList
                .empty()
                .append(this.children.tagsCheckbox.render().el);
        },

        render() {
            this.$el.html(Modal.TEMPLATE);
            this.$(Modal.HEADER_TITLE_SELECTOR).html('Select Billing Tags');
            this.$(Modal.BODY_SELECTOR).append(Modal.FORM_HORIZONTAL);
            this.$(Modal.BODY_SELECTOR).append(_.template(this.warningTemplate));
            this.$(Modal.BODY_SELECTOR).append('<div id="tag-list"></div>');
            this.$(Modal.FOOTER_SELECTOR).append(BUTTON_CANCEL);
            this.$(Modal.FOOTER_SELECTOR).append(BUTTON_SAVE);
        },

        onSave() {
            let newTags = this.model.get('modelTags'), url;
            if (billing_type[0] == "Billing_CUR")
                url = cur_url;
            else
                url = legacy_url;

            $.ajax({
                url: `${url}?output_mode=json`,
                type: 'post',
                dataType: 'json',
                data: {
                    'name': 'datamodel',
                    'tags': newTags.join('|')
                },
                success: () => {
                    this.onCancel();
                },
                error: () => {
                }
            });
        },

        onCancel() {
            this.hide();
        }
    });

    return TagModal;
});