"use strict";

define([
  'app/splunk_app_aws/js/libs/underscore',
  'app/splunk_app_aws/js/libs/jquery',
  'splunkjs/mvc',
  "app/splunk_app_aws/js/swc-aws/index",
  "splunkjs/mvc/simplexml/element/chart",
  "splunkjs/mvc/searchmanager",
  "splunkjs/mvc/simplexml/element/table",
  "splunkjs/mvc/simpleform/input/multiselect",
  "app/views/rds/InstancesSelectInput",
  "app/views/rds/EngineLogoCellRenderer",
  "app/views/rds/RowExpansionRenderer",
  "app/utils/InputUtil",
  "@splunk/ui-utils/i18n",
  "appcss/pages/rds/bootstrap.pcss",
  'app/views/dashboard/common',
  "splunkjs/mvc/simplexml/ready!"
], function(
  _,
  $,
  mvc,
  index,
  ChartElement,
  SearchManager,
  TableElement,
  MultiSelectInput,
  InstancesSelectInput,
  LogoCellRenderer,
  RowExpandsionRenderer,
  InputUtil,
  ui,
) {

  var store_metricval_on_null;
  //This function sets value of metricinput to null whenever edit button is clicked
  function preventErroronEdit(){
    store_metricval_on_null = metricInput.val();
    metricInput.val(null);
    
    if(document.readyState === "complete") {
      var checkExist = setInterval(function() {
        if (document.getElementsByClassName("edit-cancel")[0]!=undefined) {
          clearInterval(checkExist);
          work();
        }
      }, 300); 
    }

  }

  function work()
  {
    metricInput.val(store_metricval_on_null)
    document.getElementsByClassName("edit-cancel")[0].onclick = function(){ setvalonCancel();}
  }

  function setvalonCancel()
  {
    metricInput.val(null);
    var checkExist = setInterval(function() {
      if (document.getElementsByClassName("edit-btn")[0]!=undefined) {
        metricInput.val(store_metricval_on_null);
        clearInterval(checkExist);
      }
    }, 100); 
  }

  // views: form inputs
  new SearchManager({
    "id": "search_instances",
    "search": '`aws-description-resource("$accountId$", " $region$", "rds_instances")` | fields id engine | eval label=id | sort label',
    "earliest_time": "-7d",
    "latest_time": "now",
    "auto_cancel": 90,
    "preview": true,
    "runWhenTimeIsUndefined": false
  }, {tokens: true});

  /**
   * Update the $rdsIdFilter$ token when RDS instances multiselect is changed.
   * This token is used to filter events from AWS RDS description.
   */
  function updateRDSIdFilterToken(value) {
    var tokenModel = mvc.Components.getInstance("default"),
        tokenName  = "rdsIdFilter";

    if(value.length > 0) {
      let tokenValue = _(value).map(function(v) {
        return `id="${v}"`;
      }).join(" OR ");

      tokenModel.set(tokenName, `(${tokenValue})`);
    } else {
      tokenModel.unset(tokenName);
    }
  }

  /**
   * Update the the engine tokens (set / unset) on RDS instances multiselect changes.
   * Some chart views are only meaningful to some engine, so we need to know
   * what kinds of engines are currently selected.
   */
  function updateEngineToken(value, input) {
    var defaultTokenModel = mvc.Components.getInstance("default"),
        submittedTokenModel = mvc.Components.getInstance("submitted", {create: true});

    _(["mysql", "postgres", "oracle", "sqlserver"]).each(function(n) {
      defaultTokenModel.unset(n);
      submittedTokenModel.unset(n);
    });

    if(value.length < 1) { return; }

    var engines,
        allEngines = input.settings.get("rdsEngines") || {};

    if(value.indexOf("*") > -1) {
      engines = _(allEngines).values();
    } else {
      engines = _(value).map(function(v) {
        return allEngines[v];
      });
    }

    _.each(_.uniq(_.compact(engines)), function(n) {
      if(n === "mariadb") { n = "mysql"; }
      else if(n.indexOf("oracle") > -1) { n = "oracle"; }
      else if(n.indexOf("sqlserver") > -1) { n = "sqlserver"; }

      defaultTokenModel.set(n, true);
      // on page load, the "depends" tokens are read
      // from submitted token model
      submittedTokenModel.set(n, true);
    });
  }

  function onInstanceChange(newValue, input) {
    updateRDSIdFilterToken(newValue, input);
    updateEngineToken(newValue, input);
  }

  var instancesInput = new InstancesSelectInput({
    "label": ui.gettext("RDS Instances"),
    "value": "$form.dimensionFilter$",
    "choices": [{label: "All", value: "*"}],
    "managerid": "search_instances",
    "valueField": "id",
    "labelField": "label",
    "prefix": "(",
    "valuePrefix": 'metric_dimensions="DBInstanceIdentifier=[',
    "valueSuffix": ']"',
    "delimiter": " OR ",
    "suffix": ")",
    "searchWhenChanged": true,
    "handleValueChange": true,
    "default": "*",
    "el": $('#input_rds_instances')
  }, {tokens: true});

  instancesInput.on("change", function(newValue) {
    onInstanceChange(newValue, this);
  });
  // the first "change" event happens before "datachange",
  // which means when it happens, data is not ready yet.
  instancesInput.on("datachange", function() {
    onInstanceChange(this.val(), this);
  });

  instancesInput.render();

  // CREATE "Metrics" MULTISELECT

  var metricOptions = {
    CPUUtilization: {
      viewOptions: {
        "charting.axisTitleY.text": "%"
      }
    },
    FreeableMemory: {
      splAgg: "eval(round(avg(Average) / 1024 / 1024, 2))",
      viewOptions: {
        "charting.axisTitleY.text": "MB"
      }
    },
    NetworkTransmitThroughput: {
      splAgg: "eval(round(avg(Average) / 1024, 2))",
      viewOptions: {
        "charting.axisTitleY.text": "KB/Second"
      }
    },
    NetworkReceiveThroughput: {
      splAgg: "eval(round(avg(Average) / 1024, 2))",
      viewOptions: {
        "charting.axisTitleY.text": "KB/Second"
      }
    },
    FreeStorageSpace: {
      splAgg: "eval(round(avg(Average) / 1024 / 1024, 2))",
      viewOptions: {
        "charting.axisTitleY.text": "MB"
      }
    },
    SwapUsage: {
      splAgg: "eval(round(avg(Average) / 1024 / 1024, 2))",
      viewOptions: {
        "charting.axisTitleY.text": "MB"
      }
    },
    ReadIOPS: {
      viewOptions: {
        "charting.axisTitleY.text": "Count/Second"
      }
    },
    ReadLatency: {
      viewOptions: {
        "charting.axisTitleY.text": "Seconds"
      }
    },
    ReadThroughput: {
      splAgg: "eval(round(avg(Average) / 1024, 2))",
      viewOptions: {
        "charting.axisTitleY.text": "KB/Second"
      }
    },
    WriteIOPS: {
      viewOptions: {
        "charting.axisTitleY.text": "Count/Second"
      }
    },
    WriteLatency: {
      viewOptions: {
        "charting.axisTitleY.text": "Seconds"
      }
    },
    WriteThroughput: {
      splAgg: "eval(round(avg(Average) / 1024, 2))",
      viewOptions: {
        "charting.axisTitleY.text": "KB/Second"
      }
    },
    TransactionLogsDiskUsage: {
      label: "Transaction Logs Disk Usage (PostgreSQL)",
      splAgg: "eval(round(avg(Average) / 1024 / 1024, 2))",
      viewOptions: {
        tokenDependencies: {depends: "$postgres$"},
        "charting.axisTitleY.text": "MB"
      }
    },
    OldestReplicationSlotLag: {
      label: "Oldest Replication Slot Lag (PostgreSQL)",
      viewOptions: {
        tokenDependencies: {depends: "$postgres$"}
      }
    },
    BinLogDiskUsage: {
      label: "Bin Log Disk Usage (MySQL)",
      splAgg: "eval(round(avg(Average) / 1024 / 1024, 2))",
      viewOptions: {
        tokenDependencies: {depends: "$mysql$"},
        "charting.axisTitleY.text": "MB"
      }
    }
  };

  function createMetricChart(metricName) {
    var metric = metricOptions[metricName] || {};
    var searchId = `search_${metricName}`;
    if(mvc.Components.getInstance(searchId)){return;}
    var agg = metric.splAgg || "avg(Average)";
    var label = metric.label;
    if(_.isUndefined(label)) {
      label = metricName.replace(/([A-Z])([A-Z][^A-Z])/g, "$1 $2");
      label = label.replace(/([^A-Z])([A-Z])/g, "$1 $2");
    }
    label = `Average ${label}`;

    var metricSPL = `\`aws-cloudwatch-rds($accountId$, $region$)\` $dimensionFilter$ metric_name="${metricName}" | \`aws-cloudwatch-dimension-rex("DBInstanceIdentifier", "Instance")\` | timechart ${agg} as value by Instance`;

    new SearchManager({
      "id": searchId,
      "earliest_time": "$earliest$",
      "latest_time": "$latest$",
      "search": metricSPL,
      "preview": true,
      "auto_cancel": 90,
      "cancelOnUnload": true,
      "runWhenTimeIsUndefined": false
    }, {tokens: true});

    return new ChartElement(_.extend({
      "id": `chart_metric_${metricName}`,
      "title": ui.gettext(label),
      "managerid": searchId,
      "el": $(`#chart_metric_${metricName}`),
      "tokenDependencies": metric.tokenDependencies,
      "charting.axisLabelsX.majorLabelStyle.rotation": "0",
      "charting.axisLabelsX.majorLabelStyle.overflowMode": "ellipsisNone",
      "charting.axisTitleX.visibility": "collapsed",
      "charting.axisTitleY.visibility": "visible",
      "charting.axisTitleY2.visibility": "visible",
      "charting.axisX.scale": "linear",
      "charting.axisY.scale": "linear",
      "charting.axisY2.scale": "inherit",
      "charting.axisY2.enabled": "0",
      "charting.chart": "line",
      "charting.chart.bubbleMaximumSize": "50",
      "charting.chart.bubbleMinimumSize": "10",
      "charting.chart.bubbleSizeBy": "area",
      "charting.chart.nullValueMode": "gaps",
      "charting.chart.showDataLabels": "none",
      "charting.chart.sliceCollapsingThreshold": "0.01",
      "charting.chart.stackMode": "default",
      "charting.chart.style": "shiny",
      "charting.drilldown": "all",
      "charting.layout.splitSeries.allowIndependentYRanges": "0",
      "charting.layout.splitSeries": "0",
      "charting.legend.placement": "top",
      "charting.legend.labelStyle.overflowMode": "ellipsisMiddle",
      "resizable": true
    }, metric.viewOptions || {}), {tokens: true});
  }

  function removeMetricChart(metricName) {
    var chart = mvc.Components.getInstance(`chart_metric_${metricName}`);
    if(!_.isUndefined(chart)) {
      chart.remove();
    }

    var manager = mvc.Components.getInstance(`search_${metricName}`);
    if(!_.isUndefined(manager)) {
      manager.dispose();
    }
  }

  var row_counter=0;
  /*
   * handle metric selection changes.
   * when it changed, we try to keep the number of search as little as possible.
   * we do this by:
   *   * keep the untouched charts
   *   * remove the un-selected charts
   *   * add newly-selected charts
   *
   * @param view the View element of the multiselect input (.visualization).
   * @param panelNumInRow indicates how many panels should be shown in a row. (default 2)
   */
  function onMetricChange(view, panelNumInRow) {

    var buttons = document.getElementsByClassName("btn edit-btn");
    if(buttons.length>0 && buttons[0]!= undefined){ 
      buttons[0].onclick = function(){ preventErroronEdit();}
    }
    if(_.isUndefined(view._data) || _.isNull(view._data)) {
      // don't do anything if the input has no data.
      return;
    }

    if(_.isUndefined(panelNumInRow)) {
      panelNumInRow = 2;
    }

    var newValue = view.settings.get("value");
    if(newValue && newValue.indexOf("*") > -1) {
      newValue = _(view._data).map(function(obj) {
        return obj.metric_name;
      });
    }

    var oldValue = view.settings.previous("value") || [];
    if(oldValue.indexOf("*") > -1) {
      oldValue = _(view._data).map(function(obj) {
        return obj.metric_name;
      });
    }
    var toKeep = _.intersection(oldValue, newValue);
    var toAdd  = _.difference(newValue, oldValue);

    function getPanel(metricName) {
      return document.getElementById(`panel_metric_${metricName}`)
    };

    function newPanel(metricName) {
      var title_name = metricName.replace(/([A-Z])([A-Z][^A-Z])/g, "$1 $2");
      title_name = title_name.replace(/([^A-Z])([A-Z])/g, "$1 $2");
      var panel = document.createElement("div");  
      panel.setAttribute("id",`panel_metric_${metricName}`);  
      panel.setAttribute("class","dashboard-cell dashboard-layout-panel");
      panel.setAttribute("style","width: 100%;")
      var inner_panel = document.createElement("div");
      inner_panel.setAttribute("class","dashboard-panel with-title");
      var heading = document.createElement("h2");
      heading.innerHTML="Average "+title_name;
      heading.setAttribute("class","panel-title");
      var chart_element = document.createElement("div");
      chart_element.setAttribute("id",`chart_metric_${metricName}`); 
      chart_element.setAttribute("class","dashboard-element");
      chart_element.setAttribute("style","width: 100%;")
      inner_panel.appendChild(heading);
      inner_panel.appendChild(chart_element);
      panel.appendChild(inner_panel);
      return panel;
    };

    // firstly, we keep the panels which don't need to be removed
    var oldPanels = _.compact(_(toKeep).map(function(metricName) {
      var panel = getPanel(metricName);
      if(!panel) {
        // somehow, the panel is not on the dashboard, we will create it
        return newPanel(metricName);
      } else {
        $(`#${panel.id}`).detach();
        return panel;
      }
    }));

    // then, we remove all old rows, and the remaining panels
    for(let i = 0;; i++) {
      /* jshint loopfunc: true */
      let row = document.getElementById(`row_metric_${i}`);
      if(!row) { break; }
      _($(`#${row.id}`).children(".dashboard-cell")).each(function(cell) {
        var name = _(cell.id.split("_")).last();
        if(!toKeep.includes(name))
        {
          var panel = getPanel(name);
          if(panel){
            panel.remove();
            removeMetricChart(name);
          }
        }
      });
      if (!row.hasChildNodes())row.remove();
    }

    // create new panels & charts for new metrics
    // and store them to panels
    // so we get all new panels we need to show
    var panels = oldPanels.concat(_(toAdd).map(newPanel));

    // create rows and put panels into rows
    // and show them on the dashboard
    var renderRow = function(row) {
      if(row) {
        document.getElementById("layout1").appendChild(row);
      }
    };

    function addChild(row, panel){
      var tokenModel = mvc.Components.getInstance("default");
      var metric_name = _(panel.id.split("_")).last();
      var metric = metricOptions[metric_name];
      if(metric && metric.viewOptions.tokenDependencies)
      {
        var dep_token = metric.viewOptions.tokenDependencies.depends;
        if(tokenModel.get(dep_token.slice(1,dep_token.length-1)))
        {
          row.appendChild(panel);
          var metChart = createMetricChart(metric_name);
          if(metChart)metChart.render();
        }
      }
      else
      {
        row.appendChild(panel);
        var metChart = createMetricChart(metric_name);
        if(metChart)metChart.render();
      }
    }

    function createRow(rc)
    {
      var row = document.createElement("div");
      row.setAttribute("id",`row_metric_${rc}`);
      row.setAttribute("class","dashboard-row dashboard-layout-rowcolumn-row chart-row");
      return row;
    }
    
    function getLastRow(){
      var all_rows = $("#layout1").children(".dashboard-row.dashboard-layout-rowcolumn-row.chart-row");
      if(all_rows.length<1){
        row_counter = 0;
        var row = createRow(row_counter);
        row_counter+=1;
        renderRow(row);  
        return row;
      }
      else
      {
        return all_rows[all_rows.length-1];
      }
    }

    _(panels).each(function(panel) {
      var last_row=getLastRow();
      if($(`#${last_row.id}`).children(".dashboard-cell.dashboard-layout-panel").length<2)
      {
        addChild(last_row,panel);
        $(`#${last_row.id}`).children(".dashboard-cell.dashboard-layout-panel").css({"width": "100%"});
        if($(`#${last_row.id}`).children(".dashboard-cell.dashboard-layout-panel").length==2){
          $(`#${last_row.id}`).children(".dashboard-cell.dashboard-layout-panel").css({"width": "50%"});
        }
      }
      else 
      {
        var new_row = createRow(row_counter);
        row_counter+=1;
        renderRow(new_row);    
        addChild(new_row,panel);   
        $(`#${new_row.id}`).children(".dashboard-cell.dashboard-layout-panel").css({"width": "100%"});
      }  
    });
  }

  new SearchManager({
    "id": "search_metric_names",
    "search": '`aws-cloudwatch-rds($accountId$, $region$)` $dimensionFilter$ | fields metric_name | dedup metric_name | sort metric_name',
    "earliest_time": "$earliest$",
    "latest_time": "$latest$",
    "auto_cancel": 90,
    "preview": false,
    "runWhenTimeIsUndefined": false
  }, {tokens: true});

  var metricInput = new MultiSelectInput({
    "label": ui.gettext("Metrics"),
    "managerid": "search_metric_names",
    "valueField": "metric_name",
    "labelField": "metric_name",
    "choices": [{"label":"All","value":"*"}],
    "el": $('#input_metric_names'),
    "width": "100%",
  }, {tokens: true});


  metricInput.on("create:visualization", function() {
    this.visualization.val = InputUtil.multiSelectVal;
  });

  metricInput.on("change", function() {
    onMetricChange(this.visualization);
  });

  metricInput.on("datachange", function() {
    var viz = this.visualization;

    if(!this.hasValue() || _.isEmpty(this.val())) {
      // set default values, this is better than the "default" option,
      // because "default" option will show even it doesn't have those options available
      let defaultChoices = [
        "CPUUtilization",
        "FreeableMemory",
        "FreeStorageSpace",
        "SwapUsage",
        "ReadIOPS",
        "WriteIOPS",
        "ReadLatency",
        "WriteLatency"
      ];

      let availableChoices = _(viz._data).map(function(obj) { return obj.metric_name; });

      this.val(_.intersection(defaultChoices, availableChoices));
    } else {
      onMetricChange(viz);
    }
  });

  metricInput.render();
  var buttons = document.getElementsByClassName("btn edit-btn");
  if(buttons.length>0){
    buttons[0].onclick = function(){ preventErroronEdit();}
  }

  // VIEWS: VISUALIZATION ELEMENTS

  var engineNames = {
    "aurora":        "Aurora",
    "mysql":         "MySQL",
    "mariadb":       "MariaDB",
    "postgres":      "PostgreSQL",
    "oracle-se":     "Oracle SE",
    "oracle-ee":     "Oracle EE",
    "oracle-se1":    "Oracle SE One",
    "oracle-se2":    "Oracle SE Two",
    "sqlserver-se":  "SQL Server SE",
    "sqlserver-ee":  "SQL Server EE",
    "sqlserver-ex":  "SQL Server Express",
    "sqlserver-web": "SQL Server Web"
  };

  var splCaseExp = "case(" +
    _(engineNames).map(function(v, k) {
      return `engine="${k}", "${v}"`;
    }).join(",") +
    ")";

  var searchInstancesSPL = '`aws-description-resource("$accountId$", " $region$", "rds_instances")` | search $rdsIdFilter$ | eval Engine = '
    + splCaseExp + ' . "-" . engine_version, DBName = if(DBName = "null", "", DBName), multi_az = if(multi_az = "true", "Yes", "No"), create_time=if(create_time="null", "", create_time)'
    + '| table Engine, id, DBName, status, allocated_storage, instance_class, availability_zone, multi_az, create_time'
    + '| rename id as "DB Instance", DBName as "DB Name", status as "Status", instance_class as "Class", allocated_storage as "Allocated Storage (GB)", availability_zone as "Availability Zone", multi_az as "Multi-AZ", create_time as "Created Time"';

  new SearchManager({
    "id": "search_instances_list",
    "search": searchInstancesSPL,
    "earliest_time": "-7d",
    "latest_time": "now",
    "auto_cancel": 90,
    "preview": true,
    "runWhenTimeIsUndefined": false
  }, {tokens: true});

  var table = new TableElement({
    "title": ui.gettext("RDS Instance Details"),
    "count": 10,
    "dataOverlayMode": "none",
    "drilldown": "row",
    "rowNumbers": false,
    "wrap": false,
    "managerid": "search_instances_list",
    "el": $('#table_rds_instance_details')
  }, {tokens: true});

  table.on("create:visualization", function() {
    // table.visualization.addCellRenderer(
    //   new LogoCellRenderer({fieldName: 'Engine'})
    // );

    table.visualization.addRowExpansionRenderer(
      new RowExpandsionRenderer({
        accountToken: "$accountId$",
        regionToken:  "$region$"
      })
    );
  });
  table.render();

});