// This helper improves the multiselectview from Splunk MVC.
//
// Initially the multiselectview has default value '*' (all). If the user
// selects any other value, '*' should be removed and only selected value applied.
// 
// If the user select '*' again, then remove all other values.
define([
    'app/splunk_app_aws/js/libs/underscore',
    'splunkjs/mvc',
    'app/splunk_app_aws/js/swc-aws/index',
    'app/utils/InputUtil',
    'app/views/dashboard/Id_Multiselect'
], function(_, mvc, index, InputUtil, idList) {
    'use strict';

    const MultiSelectView = index.MultiSelectView;
    const list_of_ids_with_all = idList.list_of_ids_with_all;
    const list_of_ids_without_all = idList.list_of_ids_without_all;

    Object.keys(mvc.Components.attributes).forEach((componentName) => {
        var component = mvc.Components.get(componentName);
        var str=componentName;

        for(var iter1=0;iter1<list_of_ids_with_all.length;iter1++)
        {
            if(str.search(list_of_ids_with_all[iter1])!=-1)
            {
                component.val = InputUtil.multiSelectVal_persist_all; 
            }
        }
        for(var iter2=0;iter2<list_of_ids_without_all.length;iter2++)
        {
            if(str.search(list_of_ids_without_all[iter2])!=-1)
            {
                component.val = InputUtil.multiSelectVal; 
            }
        }
    });
});
