define([
    'app/splunk_app_aws/js/libs/underscore',
    'app/splunk_app_aws/js/swc-aws/index',
    'splunkjs/mvc',
    'splunkjs/mvc/dropdownview',
    'app/utils/BillingCurUtil',
    'splunkjs/mvc/simplexml/ready!'
], function(_, index, mvc, DropdownView, BillingCurUtil) {
    'use strict';

    const BaseModel = index.BaseModel;
    const BaseView = index.BaseView;
    const moment = index.moment;
    const FROM_RANGE = 12;
    const TO_RANGE = 0;
    const DATE_FORMAT = 'YYYY-MM';
    const FROM_TITLE = 'From';
    const TO_TITLE = 'To';

    let tokenModel = mvc.Components.getInstance('default');

    // @param
    //        fromRange {Integer} number of months
    //        fromCurrentMonth {Boolean} allow the user to select current month as "From"
    function generateFromOptions(fromRange, fromCurrentMonth) {
        let optionList = [];

        let nowMoment = moment();

        if (!fromCurrentMonth) {
            nowMoment.subtract(1, 'M');
        }

        for (let i = 1; i <= fromRange; i++) {
            let date = nowMoment.startOf('month');
            optionList.push({
                label: date.format(DATE_FORMAT),
                value: BillingCurUtil.getUTCUnix(date)
            });

            nowMoment.subtract(1, 'M');
        }

        return optionList;
    }

    // @param
    //        toRange {Integer} number of months
    function generateToOptions(timerangeFrom, toRange) {
        let optionList = [];

        let fromMoment = moment.unix(timerangeFrom);
        let nowMoment = moment();

        while (fromMoment.isBefore(nowMoment) || toRange > 0) {
            fromMoment = fromMoment.endOf('month');

            optionList.unshift({
                label: fromMoment.format(DATE_FORMAT),
                value: fromMoment.unix() + fromMoment.utcOffset() * 60
            });
            toRange--;
            fromMoment.add(1, 'M');
        }

        return optionList;
    }

    /**
     * @constructor
     * @name MonthSelectorCur
     * @extends BaseView
     *
     * @param {Object} options
     * @param {String} options.from -
     * @param {String} options.to -
     * @param {Integer} options.fromRange -
     * @param {Boolean} options.fromCurrentMonth - allow the user to select current month as "From"
     * @param {Integer} options.toRange -
     * @param {Boolean} options.submit - automatically submit form after change
     * @param {Boolean} options.isDetailedBilling
     */
    let MonthSelectorCur = BaseView.extend({
        initialize(options) {
            BaseView.prototype.initialize.apply(this, arguments);

            let fromOptionList = generateFromOptions(options.fromRange || FROM_RANGE, options.fromCurrentMonth);
            let defaultFrom = fromOptionList[2].value;
            let defaultTo = this.options.defaultTo;

            if (this.options.defaultFrom) {
                let result = _.findWhere(fromOptionList, { value: parseInt(this.options.defaultFrom) });
                if (result) {
                    defaultFrom = result.value;
                }
            }

            this.model = new BaseModel({
                from: defaultFrom,
                to: defaultTo
            });

            this.$from = options.from;
            this.$to = options.to;
            this.fromTitle = options.fromTitle || FROM_TITLE;
            this.toTitle = options.toTitle || TO_TITLE;
            this.isDetailedBilling = options.isDetailedBilling;

            this.timerangeFromSelector = new DropdownView({
                id: 'from',
                choices: fromOptionList,
                initialValue: defaultFrom,
                showClearButton: false,
                width: 120
            });

            this.timerangeToSelector = new DropdownView({
                id: 'to',
                showClearButton: false,
                width: 120
            });

            this.timerangeFromSelector.on('change', () => {
                this.model.set('from',this.timerangeFromSelector.settings.get('value'));
                this._updateTimerange();
                this._updateToSelection();
            }, this);

            this.timerangeToSelector.on('change', ()=> {
                this.model.set('to',this.timerangeToSelector.settings.get('value'));
                this._updateTimerange();
            }, this);
        },

        loading(loading) {
            if (loading) {
                this.model.unset('from');
                this.model.unset('to');
                this.timerangeFromSelector.settings.set('disabled',true);
                this.timerangeToSelector.settings.set('disabled',true);
            } else {
                this.timerangeFromSelector.settings.set('disabled',false);
                this.timerangeToSelector.settings.set('disabled',false);
            }
        },

        setDatamodel(isDetailedBilling) {
            this.isDetailedBilling = isDetailedBilling;
        },

        render() {
            this.$from.empty();
            this.$to.empty();

            this.$from.append(`<label for="timerange-from">${this.fromTitle}</label>`);
            this.$from.append(this.timerangeFromSelector.render().el);

            this.$to.append(`<label for="timerange-to">${this.toTitle}</label>`);
            this.$to.append(this.timerangeToSelector.render().el);

            this.$from.parent().parent()
                .css('display', 'inline-block');
            this.$from
                .css('width', '120px');

            this.$to.parent().parent()
                .css('display', 'inline-block')
                .css('margin-left', '20px');

            this.$to
                .css('width', '120px')
                .css('margin-right', '30px');

            this._updateToSelection();
            this._updateTimerange();
        },

        _updateToSelection() {
            let timerangeFrom = parseInt(this.model.get('from'));
            let options = generateToOptions(timerangeFrom, this.options.toRange || TO_RANGE);
            let isInOptions = 0;
            let timerangeTo = parseInt(this.model.get('to'));
            this.timerangeToSelector.settings.set('choices', options);
            this.timerangeToSelector.settings.set('value',timerangeTo);
            this.timerangeFromSelector.settings.set('value',timerangeFrom);
            if (!timerangeTo || timerangeFrom > timerangeTo) {
                this.model.set('to', options[0].value);
                this.timerangeToSelector.settings.set('value', options[0].value);
            }
            timerangeTo = parseInt(this.model.get('to'));
            for (var i=0; i<options.length; i++)
            {
                if (timerangeTo == options[i].value)
                {
                    isInOptions=1;
                    break;
                }
            }
            if(!isInOptions)
            {
                this.timerangeToSelector.settings.set('value', '');
            }
        },

        _updateTimerange() {
            let from = this.model.get('from');
            let to = this.model.get('to');

            if (!from || !to) {
                return;
            }

            let prefix = this.isDetailedBilling ? "detailed_billing_cur." : "";

            BillingCurUtil.updateMonthSpl(from, to, prefix, this.options.submit);
        }
    });

    return MonthSelectorCur;
});