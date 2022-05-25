require([
        'app/routers/ConfigureRouter',
        'app/splunk_app_aws/js/swc-aws/configure_index',
        'app/configure/Config',
        'appcss/pages/configure/bootstrap.pcss'
    ],
    function (
         Router,
         index,
         Config
    ) {
        const Router_utils = index.Router_utils;
        // load config context data
        Config.loadContext().done(function(){
            new Router();
            Router_utils.start_backbone_history();
        });
    });