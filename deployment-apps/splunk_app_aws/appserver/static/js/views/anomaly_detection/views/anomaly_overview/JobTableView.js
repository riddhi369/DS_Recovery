define([
    'app/splunk_app_aws/js/libs/underscore',
    'app/splunk_app_aws/js/libs/jquery',
    'app/splunk_app_aws/js/libs/backbone',
    'app/splunk_app_aws/js/swc-aws/index',
    'splunkjs/mvc',
    'app/models/AnomalyConfigs',
    'splunkjs/mvc/tableview',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc/multidropdownview',
    'app/views/anomaly_detection/views/InfoView',
    'app/views/anomaly_detection/views/JobView',
    'app/views/anomaly_detection/views/anomaly_overview/ActionCellView',
    'app/views/anomaly_detection/views/anomaly_overview/DetailRender',
    'app/views/anomaly_detection/Config'
], function (_, $, Backbone, index,mvc, JobModel, TableView, SearchManager,MultiDropdown, InfoView, JobView, ActionCellView, DetailRender, SystemConfig) {
    let submitModel = mvc.Components.getInstance('submitted');
    var tokens = mvc.Components.getInstance('default');
    tokens.set('tags', "");
    mvc.setFilter('tag2spl', function (tags) {
        var spls = ['| eval match_count = 0'];
        var tags = _.filter(tags.split(','), function (value) {
            return !_.isEmpty(value)
        });
        tags.forEach(function (tag) {
            spls.push('match_count = match_count + if(match(' + SystemConfig.JOB_TAGS + ', "^.*' + tag + '.*$"), 1, 0)');
        });
        var spl = spls.join(',') + '| where match_count=' + tags.length;
        return spl;
    });
    if (tokens && submitModel) {
        submitModel.set(tokens.toJSON());
    }
    return TableView.extend({
        initialize: function () {
            TableView.prototype.initialize.apply(this, arguments);

            // models initialize
            this.models = {};
            this.models.input = new Backbone.Model();
            this.models.job = new JobModel();
            this.models.tableModel = this.settings.get('models').tableModel;

            // views initialize
            this.children = {};
            this.children.job = new JobView({
                models: {
                    input: this.models.input
                }
            });


            this.tags = [];
            this.multidropdown = new MultiDropdown({
                id: "tagsMultidropdown",
                allowCustomValues:true,
                choices: [],
                el: $("#tags")
            },this).render();
            var customCss = {
                "display":"inline-block",
                "padding-right":"30px"
            };
            $('#custom_multidropdown').parent().parent().css(customCss);
            this.tagsSM = new SearchManager({
                id: 'tagSearch',
                preview: false,
                search: '| rest servicesNS/nobody/splunk_app_aws/configs/conf-anomalyconfigs fillcontents=1 splunk_sever=local | search '
                + SystemConfig.JOB_PRIORITY + '=$priority$ ' + SystemConfig.JOB_SCHEDULE + '=$schedule$'
            }, {tokens: true});
            this.tagsSM.on('search:done', (function () {
                var resultModel = this.tagsSM.data('results', {output_mode: 'json'});
                resultModel.once('data', (function () {
                    var results = resultModel.data().results;
                    this.tags = this._formatTags(results);
                    var final_tags = [];
                    for(var i=0;i<this.tags.length;i++){
                        final_tags.push({"label":this.tags[i],"value":this.tags[i]});
                    }
                    this.multidropdown.settings.set("choices", final_tags);
                    this.multidropdown.on('change', function test(){
                        var selectedTags = this.multidropdown.val();
                        tokens.set('tags', selectedTags.join(","));
                        if (tokens && submitModel) {
                            submitModel.set(tokens.toJSON());
                        }
                    }, this);
                }).bind(this));
            }).bind(this));


            this.children.info = new InfoView();

            // callback initialize
            this.callback = this.settings.get('callback');

            this.addCellRenderer(new ActionCellView({
                models: {
                    input: this.models.input,
                    tableModel: this.models.tableModel,
                    job: this.models.job
                },
                children: {
                    info: this.children.info,
                    job: this.children.job
                },
                callback: this.callback
            }));
            this.addRowExpansionRenderer(new DetailRender({
                models: {
                    input: this.models.input,
                    application: this.models.application,
                    tableModel: this.models.tableModel
                }
            }));
            //events
            this.listenTo(this.children.job, 'saveJob', this._updateJobContent.bind(this));
            this.listenTo(this.children.info, 'changeJobMode', this._updateJobMode.bind(this));
            this.listenTo(this.children.info, 'deleteJob', this._deleteJob.bind(this));
            this.listenTo(this.children.info, 'deleteAlert', this._deleteAlert.bind(this));
        },
        _formatTags: function(results){
            var tags = [];
            results.forEach(function (value) {
                if (SystemConfig.JOB_TAGS in value && !_.isEmpty(value[SystemConfig.JOB_TAGS])) {
                    tags = _.union(tags, value[SystemConfig.JOB_TAGS].split(','));
                }
            });
            return tags.sort();
        },
        _updateJobContent: function () {
            var id = this.models.input.get(SystemConfig.JOB_ID);
            var content = _.pick(this.models.input.toJSON(), SystemConfig.JOB_NAME, SystemConfig.JOB_DESCRIPTION, SystemConfig.JOB_PRIORITY, SystemConfig.JOB_SCHEDULE,
                SystemConfig.JOB_TRAIN, SystemConfig.JOB_TAGS);
            // update stanza
            $.when(this.models.job.updateStanza(id, content)).then((function () {
                    this.callback.allUpdate();
                    this.tagsSM.startSearch();
                }).bind(this),
                (function () {
                    this.children.info.showFail('job', 'update');
                }).bind(this));
        },
        _updateJobMode: function (id, mode) {
            var content = {};
            content[SystemConfig.JOB_MODE] = mode;
            // update stanza
            $.when(this.models.job.updateStanza(id, content)).then((function () {
                    this.callback.jobUpdate();
                }).bind(this),
                (function () {
                    this.children.info.showFail('job', 'update');
                }).bind(this));
        },
        _deleteJob: function (id, alert) {
            $.when(this.models.job.deleteStanza(id)).then(
                (function () {
                    if (!_.isEmpty(alert)) {
                        this._deleteAlert(id, alert, false);
                    }
                    // update anomaly_schedule_checker.csv (delete job and alert related info) when delete job.
                    var updateSpl = _.template(SystemConfig.UPDATE_SCHEDULE_CHECKER_JOB_SPL);
                    new SearchManager({
                        search: updateSpl({jobId: id})
                    });
                    this.callback.allUpdate();
                    this.callback.scheduleCheckerUpdate();
                    this.tagsSM.startSearch();
                }).bind(this),
                (function () {
                    this.children.info.showFail('job', 'delete');
                }).bind(this));
        },
        _deleteAlert: function (id, alert, updateStanza) {
            alert.destroy({wait: true});
            if (updateStanza) {
                var content = {};
                content[SystemConfig.JOB_ALERT_ID] = '';
                $.when(this.models.job.updateStanza(id, content).then((function () {
                        // update anomaly_schedule_checker.csv(delete alert related info) when delete alert.
                        var updateSpl = _.template(SystemConfig.UPDATE_SCHEDULE_CHECKER_ALERT_SPL);
                        new SearchManager({
                            search: updateSpl({jobId: id})
                        });
                        this.callback.jobUpdate();
                        this.callback.scheduleCheckerUpdate();
                    }).bind(this),
                    (function () {
                        this.children.info.showFail('job', 'update');
                    }).bind(this)));
            }
        },
        render: function () {
            TableView.prototype.render.apply(this, arguments);
            this.$el.append(this.children.info.render());
            this.$el.append(this.children.job.render());
        }
    });
});