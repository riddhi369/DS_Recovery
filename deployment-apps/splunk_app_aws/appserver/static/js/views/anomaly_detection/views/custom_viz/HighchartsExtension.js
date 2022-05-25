define([
    'app/splunk_app_aws/js/libs/jquery',
    'app/splunk_app_aws/js/swc-aws/index_for_visualization'
], function ($, index) {
    const Highcharts = index.HighCharts;
    var each = Highcharts.each;
    Highcharts.wrap(Highcharts.Legend.prototype, 'renderItem', function (proceed, item) {

        proceed.call(this, item);

        var isPoint = !!item.series,
            collection = isPoint ? item.series.points : this.chart.series,
            groups = isPoint ? ['graphic'] : ['group', 'markerGroup'],
            element = item.legendGroup.element;

        element.onmouseover = function () {
            each(collection, function (seriesItem) {
                if (seriesItem !== item) {
                    each(groups, function (group) {
                        seriesItem[group].animate({
                            opacity: 0.1
                        }, {
                            duration: 150
                        });
                    });
                }
            });
        };
        element.onmouseout = function () {
            each(collection, function (seriesItem) {
                if (seriesItem !== item) {
                    each(groups, function (group) {
                        seriesItem[group].animate({
                            opacity: 1
                        }, {
                            duration: 50
                        });
                    });
                }
            });
        };
    });
    return Highcharts;
});