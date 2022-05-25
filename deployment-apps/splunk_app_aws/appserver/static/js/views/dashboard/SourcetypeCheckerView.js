define([
    'app/splunk_app_aws/js/libs/underscore',
    'app/splunk_app_aws/js/swc-aws/index',
    'app/views/dashboard/MacroHelper',
    'app/views/dashboard/MessageView',
    'app/collections/Recommendations',
    'app/utils/SourcetypeUtil',
    'app/utils/SearchUtil',
    'app/models/Config',
    'app/utils/HelpLinks',
], function(
    _,
    index,
    MacroHelper,
    MessageView,
    RecommendationsCollection,
    SourcetypeUtil,
    SearchUtil,
    Config,
    HelpLinks
) {
    'use strict';
    const BaseModel = index.BaseModel;
    const BaseView = index.BaseView;

    let SourcetypeCheckerView = BaseView.extend({
        initialize() {
            BaseView.prototype.initialize.apply(this, arguments);

            this.model = new BaseModel({
                inputs: [],
                recommendation: null,
            });

            this.instance_type = '';
				SearchUtil.search('|inputlookup instance_type', {
                'earliest_time': '-1d'
            }).then((resultData) => {
                if (resultData.length != 0 && resultData[0]['value'] == 'on-prem') {
                    this.instance_type = 'on-prem';
                } 
            }, function(err) {
                console.log("Received an error during verification of Instance type" + err);
            });
            this.cachedSourcetypes = null;
            this.cachedRecommendation = null;
            this.messageView = MessageView;
            this._getInputsOnce = _.once(this._getInputs);
            this._getRecommendationOnce = _.once(this._getRecommendation);

            this.listenTo(MacroHelper, 'change:sourcetype', (sourcetypes) => {
                this._getInputsOnce();
                this._verifyInputs(this.cachedSourcetypes, sourcetypes);
            });

            this.listenTo(MacroHelper, 'change:recommendation', (recommendation) => {
                if (!recommendation) {
                    return;
                }

                this._getRecommendationOnce();
                this._verifyRecommendation(this.cachedRecommendation);
            });

            this.listenTo(this.model, 'change', this.render);
        },

        render() {
            let inputs = this.model.get('inputs');
            let recommendation = this.model.get('recommendation');

            if (inputs && inputs.length > 0) {
                let body = `Some panels may not be displayed correctly because the following inputs have not been configured: ${inputs.join(", ")}.<br/>` +
                    'Or, the saved search "Addon Metadata - Summarize AWS Inputs" is not enabled on Add-on instance.';

                this.messageView.setMessage('sourcetypeChecker', body, HelpLinks.AWS_DASHBOARD_SOURCETYPECHECKER);
            }

            if (recommendation) {
                let body = 'Some panels in this dashboard may not be displayed correctly. ';

                if (recommendation.indexOf('ML lib does not exist') >= 0 &&  this.instance_type == 'on-prem') {
                    body += 'The App "Python for Scientific Computing" is not installed or incorrectly configured.';
                    this.messageView.setMessage('recommendation', body, HelpLinks.AWS_RECOMMENDATION_DEPENDENCY);
                }
                else if (recommendation.indexOf('AWS Admin Validation Failed') >= 0) {
                    body += 'Only AWS admin can visit the insights.';
                    this.messageView.setMessage('recommendation', body, HelpLinks.AWS_RECOMMENDATION_DEPENDENCY);
                }
                else if (recommendation.indexOf('Not supported in Splunk Light') >= 0) {
                    body += 'It is not supported in Splunk Light.';
                    this.messageView.setMessage('recommendation', body, HelpLinks.AWS_RECOMMENDATION_DEPENDENCY);
                }
            }

            return this;
        },

        _getInputs() {
            SearchUtil.search('`aws-input-summary` | dedup input_sourcetype | fields input_sourcetype', {
                'earliest_time': '-1d'
            }).then((resultData) => {
                if (resultData && resultData.length > 0) {
                    this.cachedSourcetypes = _.pluck(resultData, 'input_sourcetype').reduce((acc, item) => {
                        acc[SourcetypeUtil.findInputBySourcetype(item)] = true;
                        return acc;
                    }, {});
                } else {
                    this.cachedSourcetypes = [];
                }
            });
        },

        _getRecommendation() {
            let recommendations = new RecommendationsCollection();
            recommendations.fetch({data: {count: -1}}).catch((result) => {
                this.cachedRecommendation = result;
            });
        },

        _verifyInputs(cachedSourcetypes, sourcetypes) {
            if (!cachedSourcetypes) {
                return;
            }

            let missing = sourcetypes.map(sourcetype => {
                sourcetype = SourcetypeUtil.findInputBySourcetype(sourcetype);
                if (!(sourcetype in cachedSourcetypes)) {
                    return sourcetype;
                }
                return null;
            }).filter(item => !!item);

            this.model.set('inputs', missing);
        },

        _verifyRecommendation(cache) {
            if (cache && cache.responseText) {
                this.model.set('recommendation', cache.responseText);
            }
        }
    });

    return SourcetypeCheckerView;
});
