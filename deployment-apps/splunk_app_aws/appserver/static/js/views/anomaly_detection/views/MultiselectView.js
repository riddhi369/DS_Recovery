define(['app/splunk_app_aws/js/swc-aws/index_for_visualization'], function (index){
    const React = index.React;
    const ReactRender = index.ReactRender;
    const Multiselect = index.MultiselectReact;
    return {
        createMultiselectComponent: function(selectedTags, allTags, container, onChange){
            var multiSelectComponent;
            var MultiselectOption = []
            for(var i=0;i<allTags.length;i++){
                var props = {
                    "label":allTags[i],
                    "value":allTags[i],
                }
                MultiselectOption.push(React.createElement(Multiselect.Option, props, null));
            }
            if(selectedTags.size==1 && Array.from(selectedTags)[0]==""){
                multiSelectComponent = 
                    React.createElement(Multiselect, 
                    {"allowNewValues":true,"onChange":onChange},
                    MultiselectOption);
            }
            else{
                multiSelectComponent = 
                    React.createElement(Multiselect, 
                    {"allowNewValues":true,"onChange":onChange,
                    "defaultValues":Array.from(selectedTags)}, 
                    MultiselectOption);
            }
            return ReactRender(multiSelectComponent, container);
        }
    };
});