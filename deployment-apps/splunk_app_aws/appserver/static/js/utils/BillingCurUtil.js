define([
    'app/splunk_app_aws/js/libs/underscore',
    'splunkjs/mvc',
    'app/utils/LookupUtil',
    'app/splunk_app_aws/js/swc-aws/index'
], function(_, mvc, LookupUtil, index) {
    'use strict';
    const DATE_FORMAT = 'YYYYMMDD';
    const moment = index.moment;
    let tokenModel = mvc.Components.getInstance('default');
    let submitModel = mvc.Components.getInstance('submitted');

    // from: from timestamp
    // to: to timestamp
    // notice that it won't generate any months that >= this month
    function generateMonths(from, to) {
        let fromMoment = moment.unix(from).utc();
        let toMoment = moment.unix(to).utc();
        let monMoment = moment().utc().startOf('month');
        let months = [];

        while (fromMoment.diff(toMoment) < 0 && fromMoment.isBefore(monMoment)) {
            months.push(fromMoment.format(DATE_FORMAT));
            fromMoment.add(1, 'M');
        }

        return months;
    }

    // get unix time in UTC
    function getUTCUnix(date) {
        return date.unix() + date.utcOffset() * 60;
    }

    function getDedupSpl(s3keyByMonth, assemblyId, prefix) {
        let monthSpl = Object.keys(s3keyByMonth).map(function(month) {
            let keys = s3keyByMonth[month];
            return '(source="*' + month + '*" AND source="*'+assemblyId[s3keyByMonth[month]]+'*")'; 
        }).join(" OR ");
        return "(" + monthSpl + ")"
    }

    // from: from timestamp
    // to: to timestamp
    // prefix: 'detailed_billing_cur' for detailed billing
    // submit: submitted to FormUtil
    function updateMonthSpl(from, to, prefix, submit) {
		var months = generateMonths(from, to);
		LookupUtil.tryLookup("| inputlookup billing_report_assemblyid_cur", {
			cache: !0
		}, "Billing CUR: Billing Reports AssemblyId Generator", "billing_report_assemblyid_cur", function(results) {
			if (results) {
				var s3keyByMonth = months.reduce(function(acc, month) {
					month = month.toString().replace("-","")+"-";
					return acc[month] = [], acc
				}, {});
				results.map(function(result) {
					months.forEach(function(month) {
						month = month.toString().replace("-","")+"-";
						result.source.indexOf(month) > -1 && s3keyByMonth[month].push(result.assemblyId)
					})
				});
				var monthSpl = Object.keys(s3keyByMonth).map(function(month) {
					var keys = s3keyByMonth[month],
						spl = keys.map(function(key) {
                            if (prefix == '')
                                return prefix + 'source="*' + key + '*"'
                            else 
                                return prefix + 'AssemblyId="*' + key + '*"'
						}).join(" OR ");
					return '(source="*' + month + '*" AND (' + spl + '))'
				}).join(" OR ");
				monthSpl = "(" + monthSpl + ")";
				tokenModel.set('monthSpl', monthSpl);
				if (submit) {
                    if (tokenModel && submitModel) {
                        submitModel.set(tokenModel.toJSON());
                    }
				}
			}
		})
	}

    return {
        updateMonthSpl: updateMonthSpl,
        getUTCUnix: getUTCUnix,
        getDedupSpl: getDedupSpl
    }
});
