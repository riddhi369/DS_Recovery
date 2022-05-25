define([
    'app/splunk_app_aws/js/libs/underscore',
    'splunkjs/mvc',
    'app/splunk_app_aws/js/swc-aws/index_for_visualization',
    'app/utils/Util',
    'app/utils/HelpLinks',
    'app/views/anomaly_detection/Config'
], function(_, mvc, index, Utils, HelpLinks, SystemConfig) {
    const Modal = index.Modal;
    var BUTTON_CANCEL = '<a href="#" class="btn cancel-job pull-left">Cancel</a>',
        BUTTON_ACK = '<a href="#" class="btn btn-primary ack-info pull-left">Acknowledge</a>',
        BUTTON_OK = '<a href="#" class="btn btn-primary modal-btn-primary pull-right">OK</a>',
        BUTTON_CREATE = '<a href="#" class="btn create-job pull-right">Create</a>',
        BUTTON_CLASS = ['create-alert', 'edit-alert', 'delete-alert', 'create-job', 'edit-job', 'delete-job',
            'change-job-mode'];
    return Modal.extend({
        initialize: function (options) {
            Modal.prototype.initialize.apply(this, arguments);
        },

        events: $.extend({}, Modal.prototype.events, {
            'click .cancel-job': function (e) {
                e.preventDefault();
                this.hide();
            },
            "click .ack-info": function(e) {
                e.preventDefault();
                var service = mvc.createService();
                var confs = service.configurations({
                    owner: "nobody",
                    app: "splunk_app_aws"
                });
                    
                // Update the upgrade status 
                confs.fetch(function (err, confs) 
                {
                    var conf = confs.item("app");
                    conf.fetch(function (err, apps) 
                    {
                        var properties = apps.properties();
                        for (var i = 0; i < properties.entry.length; i++)
                        {
                            var stanza_name = properties.entry[i].name;
                            if(stanza_name == "upgrade")
                            {
                                confs.post("app/" + "upgrade",
                                {
                                    status: 1,
                                });
                            }
                        }
                    });
                });
                this.hide();
            },
            'click a.create-alert': function (e) {
                e.preventDefault();
                this.hide();
                this.trigger('createAlert', this.name);
            },
            'click a.edit-alert': function (e) {
                e.preventDefault();
                this.hide();
                this.trigger('editAlert');
            },
            'click a.delete-alert': function (e) {
                e.preventDefault();
                this.hide();
                this.trigger('deleteAlert', this.id, this.alert, true);
            },
            'click a.delete-job': function (e) {
                e.preventDefault();
                this.hide();
                this.trigger('deleteJob', this.id, this.alert);
            },
            'click a.edit-job': function (e) {
                e.preventDefault();
                this.hide();
                this.trigger('editJob', this.name);
            },
            'click .create-job': function (e) {
                e.preventDefault();
                this.hide();
                this.trigger('createJob');
            },
            'click .change-job-mode': function (e) {
                e.preventDefault();
                this.hide();
                this.trigger('changeJobMode', this.id, this.mode);
            }
        }),

        render: function () {
            this.$el.html(Modal.TEMPLATE);
            this.$(Modal.FOOTER_SELECTOR).append(BUTTON_CANCEL);
            this.$(Modal.FOOTER_SELECTOR).append(BUTTON_OK);
            this.$(Modal.FOOTER_SELECTOR).append(BUTTON_CREATE);
            this.$('.create-job').hide();
            return this;
        },

        render_info_view: function () {
            this.$el.html(Modal.TEMPLATE);
            this.$(Modal.FOOTER_SELECTOR).append(BUTTON_ACK).css("display", "block");
            this.$('.create-job').hide();
            return this;
        },

        showFail: function (object, operation) {
            this._clean();
            this.$(Modal.HEADER_TITLE_SELECTOR).html('Fail to ' + operation);
            this.$('.btn-primary').html('OK');
            this.$(Modal.BODY_SELECTOR).html('Operations on ' + object + ' has been failed. Please try again.');
            this.show();
        },

        showAlertLoadFail: function (name) {
            this._clean();
            this.$(Modal.HEADER_TITLE_SELECTOR).html('Fail to load');
            this.$('.btn-primary').html('Create');
            this.$('.btn-primary').addClass('create-alert');
            this.$(Modal.BODY_SELECTOR).html('Fail to load "' + name + '" associate alert.<br>This is because alert\'s permission or accident deletion.\
            <br>Do you want to create another alert associate with current job ?');
            this.name = name;
            this.show();
        },

        showJobSaveSuccess: function (jobMode, alertMode) {
            this._clean();
            var jobAction = ((jobMode & SystemConfig.EDIT_MODE) > 0 ? 'updated' : 'saved');
            var alertAction = ((alertMode & SystemConfig.EDIT_MODE) > 0 ? 'Edit Alert' : 'Create Alert');
            this.$(Modal.HEADER_TITLE_SELECTOR).html('Job has been ' + jobAction);
            this.$('.btn-primary').html(alertAction);
            var html = '';
            if ((alertMode & SystemConfig.EDIT_MODE) > 0) {
                this.$('.btn-primary').addClass('edit-alert');
                html += 'You can continue to edit the binding alert.<br>';
            } else {
                this.$('.btn-primary').addClass('create-alert');
                html += 'You can continue to create an alert associated with the job.<br>';
            }
            html += 'If you want to receive customized email, please select action "Send email".';
            this.$(Modal.BODY_SELECTOR).html(html);
            this.show();
        },

        showJobDeleteConfirm: function (id, name, alert) {
            this._clean();
            this.$(Modal.HEADER_TITLE_SELECTOR).html('Delete job');
            this.$('.btn-primary').html('Delete');
            this.$('.btn-primary').addClass('delete-job');
            var content = 'Are you sure you want to delete job (' + name + ')';
            if (!_.isEmpty(alert)) {
                content += ' and corresponding alert (' + alert.entry.get('name') + ')'
            }
            content += ' ?';
            this.$(Modal.BODY_SELECTOR).html(content);
            this.id = id;
            this.alert = alert;
            this.show();
        },

        showAlertDeleteConfirm: function (id, name, alert) {
            this._clean();
            if (_.isEmpty(alert)) {
                this.showAlertLoadFail(name);
            } else {
                this.$(Modal.HEADER_TITLE_SELECTOR).html('Delete alert');
                this.$('.btn-primary').html('Delete');
                this.$('.btn-primary').addClass('delete-alert');
                this.$(Modal.BODY_SELECTOR).html('Are you sure you want to delete alert (' + alert.entry.get('name') + ')?');
                this.id = id;
                this.alert = alert;
            }
            this.show();
        },

        showJobModeChangeConfirm: function (operation, id, name, mode) {
            this._clean();
            this.$(Modal.HEADER_TITLE_SELECTOR).html(operation + ' job');
            this.$('.btn-primary').html(operation);
            this.$('.btn-primary').addClass('change-job-mode');
            this.$(Modal.BODY_SELECTOR).html('Are you sure you want to ' + operation.toLowerCase() + ' job(' + name + ') ?');
            this.id = id;
            this.mode = mode;
            this.show();
        },

        showJobEditConfirm: function (name) {
            this._clean();
            this.$(Modal.HEADER_TITLE_SELECTOR).html('Edit job');
            this.$('.btn-primary').html('Edit');
            this.$('.btn-primary').addClass('edit-job');
            //this.$('.create-job').show();
            this.$(Modal.BODY_SELECTOR).html('Another job (' + name + ') has been saved with same search. ' +
                '<br>Do you want to edit this job?');
            this.name = name;
            this.show();
        },

        showUpgradeInfo: function () {
            this._clean();
            this.$(Modal.HEADER_TITLE_SELECTOR).html('Information');
            var helplink_before_upgrade = Utils.buildLinkNode(HelpLinks.AWS_BEFORE_UPGRADE),
            helplink_after_upgrade = Utils.buildLinkNode(HelpLinks.AWS_AFTER_UPGRADE);
            this.$(Modal.BODY_SELECTOR).html("You installed the Splunk App for AWS version 6.0.3<br><br> Confirm you migrated the indexes for the app and disabled the required saved searches. "+ helplink_before_upgrade +"<br><br>Now, enable data model acceleration, schedule reports, and update the aws-data-model-acceleration search macro. " + helplink_after_upgrade);
            this.show();
        },

        _clean: function () {
            this.$('.btn-primary').removeClass(BUTTON_CLASS.join(' '));
            this.$('.create-job').hide();
        }
    });
});
