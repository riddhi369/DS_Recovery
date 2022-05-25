/**
 * Created by peter on 8/31/15.
 * Utility functions
 */
define(['app/splunk_app_aws/js/libs/underscore','@splunk/ui-utils/i18n'], function (_, ui) {

    var APP_NAME = 'splunk_app_aws';
    var APP_VERSION = '6.0.3';

    var APP_PREFIX = encodeURIComponent('[' + APP_NAME + ':' + APP_VERSION + ']');

    return {

        buildLinkNode: function(link, text) {
            /* TO DO make learn more internationazable*/
            text = text || ui.gettext('Learn more');
            return "<a class='external' target='_blank' href='/help?location=" + APP_PREFIX + link + "'>" + text + "</a>";
        }
    };

});
