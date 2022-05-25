define(["app/splunk_app_aws/js/swc-aws/index"], function(index) {
    const splunkd_utils = index.splunkd_utils;
    const utils = index.utils;
    String.prototype.format = function(args) {
        var result = this, reg;
        if (arguments.length > 0) {
            if (arguments.length === 1 && typeof (args) === "object") {
                for (var key in args) {
                    if (typeof args[key] !== 'undefined') {
                        reg = new RegExp("({" + key + "})", "g");
                        result = result.replace(reg, args[key]);
                    }
                }
            }
            else {
                for (var i = 0; i < arguments.length; i++) {
                    if (typeof arguments[i] !== 'undefined') {
                        reg = new RegExp("({)" + i + "(})", "g");
                        result = result.replace(reg, arguments[i]);
                    }
                }
            }
        }
        return result;
    };

    Date.prototype.format = function(fmt) {
        var o = {
            "M+": this.getMonth() + 1,
            "d+": this.getDate(),
            "h+": this.getHours(),
            "m+": this.getMinutes(),
            "s+": this.getSeconds(),
            "q+": Math.floor((this.getMonth() + 3) / 3),
            "S": this.getMilliseconds()
        };
        if (/(y+)/.test(fmt)) fmt = fmt.replace(RegExp.$1, (this.getFullYear() + "").substr(4 - RegExp.$1.length));
        for (var k in o)
            if (new RegExp("(" + k + ")").test(fmt)) fmt = fmt.replace(RegExp.$1, (RegExp.$1.length === 1) ? (o[k]) : (("00" + o[k]).substr(("" + o[k]).length)));
        return fmt;
    };

    $.debounce = function(func, id, wait) {
        var self = this;
        if(typeof this.debounceTimers==="undefined"){
            this.debounceTimers = {};
        }
        if(this.debounceTimers[id]) {
            clearTimeout(this.debounceTimers[id]);
            delete this.debounceTimers[id];
        }
        return function() {
            var timer = setTimeout(func, wait);
            self.debounceTimers[id] = timer;
        };
    };

    let root = document.location.origin || document.location.protocol+'//'+document.location.host,  // document.location.origin supported in IE 11.0+
        locale = utils.getPageInfo().locale || "en-US",
        appName = utils.getPageInfo().app;
        var topology_config_details={
            context: {
                root: root,
                locale: locale,
                appName: appName
            },
            defaultFilterTypes: {
                vpc: !1,
                i: !1,
                subnet: !1,
                vol: !1,
                elb: !1,
                sg: !1,
                eni: !1,
                acl: !1,
                rtb: !1,
                user: !1,
                group: !1,
                policy: !1
            },
            resourceTypeToPrefix: {
                "AWS::EC2::VPC": "vpc",
                "AWS::EC2::Instance": "i",
                "AWS::EC2::Subnet": "subnet",
                "AWS::EC2::Volume": "vol",
                "AWS::EC2::SecurityGroup": "sg",
                "AWS::EC2::NetworkInterface": "eni",
                "AWS::EC2::NetworkAcl": "acl",
                "AWS::EC2::RouteTable": "rtb",
                "AWS::EC2::InternetGateway": "igw",
                "AWS::IAM::User": "user",
                "AWS::IAM::Group": "group",
                "AWS::EC2::LoadBalancer": "elb",
                "AWS::ElasticLoadBalancingV2::LoadBalancer": "elb"
            },
            resourceTypeToName: {
                "AWS::EC2::VPC": "VPC",
                "AWS::EC2::Instance": "EC2 Instance",
                "AWS::EC2::Volume": "EBS Volume",
                "AWS::EC2::Subnet": "Subnet",
                "AWS::EC2::LoadBalancer": "Classic Load Balancer",
                "AWS::ElasticLoadBalancingV2::LoadBalancer": "Application Load Balancer",
                "AWS::EC2::SecurityGroup": "Security Group",
                "AWS::EC2::NetworkInterface": "Network Interface",
                "AWS::EC2::NetworkAcl": "ACL",
                "AWS::EC2::RouteTable": "Route Table",
                "AWS::EC2::InternetGateway": "Internet Gateway",
                "AWS::IAM::User": "IAM User",
                "AWS::IAM::Group": "IAM Group",
                "AWS::IAM::Policy": "IAM Policy"
            },
            listPanelConfig: {
                vpc: {
                    pid: "topology-accordion",
                    id: "topology-vpc-accordion",
                    title: "VPC",
                    iconURL: root + "/" + locale + "/static/app/" + appName + "/img/vpc-icon.svg"
                },
                i: {
                    pid: "topology-accordion",
                    id: "topology-instance-accordion",
                    title: "Instance",
                    iconURL: root + "/" + locale + "/static/app/" + appName + "/img/i-icon.svg"
                },
                subnet: {
                    pid: "topology-accordion",
                    id: "topology-subnet-accordion",
                    title: "Subnet",
                    iconURL: root + "/" + locale + "/static/app/" + appName + "/img/subnet-icon.svg"
                },
                vol: {
                    pid: "topology-accordion",
                    id: "topology-volume-accordion",
                    title: "Volume",
                    iconURL: root + "/" + locale + "/static/app/" + appName + "/img/vol-icon.svg"
                },
                elb: {
                    pid: "topology-accordion",
                    id: "topology-elb-accordion",
                    title: "Load Balancer",
                    iconURL: root + "/" + locale + "/static/app/" + appName + "/img/elb-icon.svg"
                },
                sg: {
                    pid: "topology-accordion",
                    id: "topology-sg-accordion",
                    title: "Security Group",
                    iconURL: root + "/" + locale + "/static/app/" + appName + "/img/sg-icon.svg"
                },
                eni: {
                    pid: "topology-accordion",
                    id: "topology-eni-accordion",
                    title: "Network Interface",
                    iconURL: root + "/" + locale + "/static/app/" + appName + "/img/eni-icon.svg"
                },
                acl: {
                    pid: "topology-accordion",
                    id: "topology-acl-accordion",
                    title: "ACL",
                    iconURL: root + "/" + locale + "/static/app/" + appName + "/img/acl-icon.svg"
                },
                rtb: {
                    pid: "topology-accordion",
                    id: "topology-rtb-accordion",
                    title: "Route Table",
                    iconURL: root + "/" + locale + "/static/app/" + appName + "/img/rtb-icon.svg"
                },
                user: {
                    pid: "topology-accordion",
                    id: "topology-user-accordion",
                    title: "IAM User",
                    iconURL: root + "/" + locale + "/static/app/" + appName + "/img/user-icon.svg"
                },
                group: {
                    pid: "topology-accordion",
                    id: "topology-group-accordion",
                    title: "IAM Group",
                    iconURL: root + "/" + locale + "/static/app/" + appName + "/img/group-icon.svg"
                },
                policy: {
                    pid: "topology-accordion",
                    id: "topology-policy-accordion",
                    title: "IAM Policy",
                    iconURL: root + "/" + locale + "/static/app/" + appName + "/img/policy-icon.svg"
                }
            },
            detailsPanelConfig: {
                activityQuery: {
                    vpc: '`aws-cloudtrail-sourcetype` awsRegion=* userIdentity.principalId="*" eventSource=ec2* | `cloudtrail_service("VPC", 1)` | spath "responseElements.networkInterface.vpcId" | search {0} |  timechart count by eventName',
                    i: '`aws-cloudtrail-sourcetype` awsRegion=* userIdentity.principalId="*" eventSource=ec2* | `cloudtrail_service("Instances", 1)` | spath "responseElements.instancesSet.items.[object Object].instanceId" | search {0} |  timechart count by eventName',
                    subnet: '`aws-cloudtrail-sourcetype` awsRegion=* userIdentity.principalId="*" eventSource=ec2* | `cloudtrail_service("VPC", 1)` | spath "responseElements.networkInterface.subnetId" | search {0} |  timechart count by eventName',
                    vol: '`aws-cloudtrail-sourcetype` awsRegion=* userIdentity.principalId="*" eventSource=ec2* | `cloudtrail_service("EBS", 1)` | spath "requestParameters.volumeSet.items.[object Object].volumeId" | search {0} |  timechart count by eventName'
                },
                usageQuery: {
                    i: '`aws-cloudwatch-ec2("*", "*")` metric_dimensions="InstanceId=[{0}]" metric_name="CPUUtilization" | timechart avg(Average) as "Avg CPU %"',
                    vol: '`aws-cloudwatch-ebs("*", "*")` metric_dimensions="VolumeId=[{0}]" (metric_name="VolumeWriteOps" OR metric_name="VolumeReadOps") | eval iops_half=Average/period | timechart eval(round(avg(iops_half)*2,2)) as "IOPS"'
                },
                vpcFlowQuery: {
                    eni: '`aws-vpc-flow-log-index` source="dest_port" interface_id="{0}" | timechart sum(eval(round(bytes/1024/1024,2))) as "Traffic by Interface (MB)"',
                    i: '`aws-vpc-flow-log-index` source="dest_port" {0} | timechart sum(eval(round(bytes/1024/1024,2))) as "Traffic by EC2 (MB)" by interface_id'
                },
                billingQuery: {
                    i: '`aws-billing-details("*")` ResourceId="{0}" | timechart span=1d sum(BlendedCost) as Cost | eval Cost=round(Cost, 2)',
                    vol: '`aws-billing-details("*")` ResourceId="{0}" | timechart span=1d sum(BlendedCost) as Cost | eval Cost=round(Cost, 2)'
                },
                latencyQuery: {
                    elb: '`aws-cloudwatch-elb("*", "*")` metric_name=Latency metric_dimensions="*LoadBalancerName=[{0}]*" | eval latency=Average*1000 | timechart avg(latency) as "Latency (ms)"',
                    alb: '`aws-cloudwatch-elb("*", "*")` metric_name=TargetResponseTime metric_dimensions="*LoadBalancer=[{0}]*" | eval latency=Average*1000 | timechart avg(latency) as "Latency (ms)"'
                },
                requestQuery: {
                    elb: '`aws-cloudwatch-elb("*", "*")` metric_name=RequestCount metric_dimensions="*LoadBalancerName=[{0}]*" | timechart sum(Sum) as "Request Count"',
                    alb: '`aws-cloudwatch-elb("*", "*")` metric_name=RequestCount metric_dimensions="*LoadBalancer=[{0}]*" | timechart sum(Sum) as "Request Count"'
                },
                nodes: {},
                drilldownLinks: {
                    i: "individual_instance_usage?form.accountId=*&form.region=*&form.instances={0}",
                    vol: "individual_ebs_usage?form.accountId=*&form.region=*&form.volumes={0}",
                    vpc: "resource_activity?form.resourceType=AWS%3A%3AEC2%3A%3AVPC&form.changeType=*&form.tags=&form.filter=configurationItem.resourceId%3D%22{0}%22",
                    subnet: "resource_activity?form.resourceType=AWS%3A%3AEC2%3A%3ASubnet&form.changeType=*&form.tags=&form.filter=configurationItem.resourceId%3D%22{0}%22",
                    sg: "resource_activity?form.resourceType=AWS%3A%3AEC2%3A%3ASecurityGroup&form.changeType=*&form.tags=&form.filter=configurationItem.resourceId%3D%22{0}%22",
                    eni: "resource_activity?form.resourceType=AWS%3A%3AEC2%3A%3ANetworkInterface&form.changeType=*&form.tags=&form.filter=configurationItem.resourceId%3D%22{0}%22",
                    acl: "resource_activity?form.resourceType=AWS%3A%3AEC2%3A%3ANetworkAcl&form.changeType=*&form.tags=&form.filter=configurationItem.resourceId%3D%22{0}%22",
                    rtb: "resource_activity?form.resourceType=AWS%3A%3AEC2%3A%3ARouteTable&form.changeType=*&form.tags=&form.filter=configurationItem.resourceId%3D%22{0}%22",
                    igw: "resource_activity?form.resourceType=AWS%3A%3AEC2%3A%3AInternetGateway&form.changeType=*&form.tags=&form.filter=configurationItem.resourceId%3D%22{0}%22",
                    elb: "individual_elb_usage?form.elb_names={0}",
                    alb: "individual_elb_usage?form.elb_names={0}"
                }
            },
            topologyChartConfig: {
                line: {
                    highlightColor: "#E76B6B",
                    dimColor: "#eee",
                    color: "#dadada"
                },
                nodeText: {
                    dimOpacity: 0,
                    maxLength: 10,
                    color: "#787878",
                    changedColor: "#E76B6B"
                },
                nodeImage: {
                    imageSize: {
                        defaultSize: 38,
                        group: 40,
                        vol: 36
                    },
                    dimOpacity: .1
                },
                ruleColorMap: {
                    High: "#D0011B",
                    Medium: "#F6A623",
                    Low: "#7ED321",
                    Informational: "#333",
                    NON_COMPLIANT: "#D0011B",
                    COMPLIANT: "#7ED321"
                },
                maxInstanceNum: 200,
                topologyStore: {
                    exportKey: "topologyExport"
                },
                kpiLayer: {
                    circleSize: {
                        max: 63,
                        min: 22
                    }
                },
                vpcScope: {
                    padding: 80
                },
                warningMessage: {
                    no_cpu_data: 'There is no CloudWatch data for EC2 CPU utilization. Please check your CloudWatch input configuration, and verify that the saved search "CloudWatch: Topology CPU Metric Generator" is scheduled and enabled.',
                    no_network_data: 'There is no CloudWatch data for network traffic. Please check your CloudWatch input configuration, and verify that the saved searches "CloudWatch: Topology Network Traffic Metric Generator" and "CloudWatch: Topology Volume Traffic Metric Generator" are scheduled and enabled.',
                    no_iam_data: 'No IAM data to display. Verify that you have checked the "Include global resources" option for your AWS Config service in the AWS Management Console.',
                    no_billing_data: 'There is no Billing data for EC2. Please check your Billing input configuration, and verify that the saved search "Billing: Topology Billing Metric Generator" is scheduled and enabled.',
                    no_inspector_data: 'There is no Amazon Inspector data. Please check your Amazon Inspector input configuration, and verify that the saved search "Amazon Inspector: Topology Amazon Inspector Recommendation Generator" is scheduled and enabled.',
                    no_config_rule_data: 'There is no Config Rules data. Please check your Config Rules input configuration, and verify that the saved search "Config Rules: Topology Config Rules Generator" is scheduled and enabled.'
                },
                playbackConfig: {
                    playbackSPL: '`topology-playback-index` earliest=$earliest_playback$ latest=$latest_playback$| stats latest(resourceName) as resourceName, latest(resourceStatus) as resourceStatus, latest(awsAccountId) as awsAccountId, latest(awsRegion) as awsRegion, latest(instanceStatus) as instanceStatus, latest(vpcId) as vpcId, latest(relationships) as relationships by resourceId, timestamp | search resourceStatus = "ResourceDeleted" OR ($accountId$ AND $region$ $vpc$) | fields resourceId relationships resourceName resourceStatus instanceStatus timestamp awsAccountId | sort 0 + timestamp',
                    snapshotSPL: '`topology-daily-snapshot-index` OR `topology-history-index` earliest=$earliest_playback$ latest=$latest_playback$ | append [search `topology-playback-index` canMiss=1 latest=$latest_playback$] | dedup resourceId | search resourceStatus!="ResourceDeleted" AND $accountId$ AND $region$ AND (resourceId!=i-* OR $state$) $vpc$ | eval timestamp=floor(_time/60)*60 | fields resourceId relationships resourceName resourceStatus instanceStatus timestamp awsAccountId',
                    eventFrameSPL: '`topology-playback-index` (resourceStatus = "ResourceDeleted" AND {0}) OR ($accountId$ AND $region$ $vpc$ AND {1}) earliest=-6mon@mon| eval timestamp=floor(_time/60)*60 | stats latest(resourceStatus) as resourceStatus, latest(instanceStatus) as instanceStatus, latest(resourceName) as resourceName by resourceId, timestamp | sort 0 + timestamp',
                    frameSearchMap: {
                        igw: "resourceId = igw-*",
                        vpc: "resourceId = vpc-*",
                        i: "resourceId = i-*",
                        subnet: "resourceId = subnet-*",
                        vol: "resourceId = vol-*",
                        sg: "resourceId = sg-*",
                        eni: "resourceId = eni-*",
                        acl: "resourceId = acl-*",
                        rtb: "resourceId = rtb-*"
                    },
                    changedResourceColorMap: {
                        vpc: "#CEAE71",
                        i: "#FF9947",
                        subnet: "#CEAE71",
                        vol: "#B43030",
                        sg: "#8B572A",
                        eni: "#FF9947",
                        acl: "#CEAE71",
                        rtb: "#CEAE71",
                        igw: "#CEAE71"
                    },
                    minColumnWidth: 4,
                    eventTypes: {
                        createResource: "Create Resource",
                        startEC2: "Start Instance",
                        stopEC2: "Stop Instance",
                        renameResource: "Rename Resource",
                        deleteResource: "Delete Resource"
                    },
                    maxTimeRange: 15552e3
                },
                forceChart: {
                    linkStrength: {
                        vpc: {
                            vpc: 10
                        },
                        i: {
                            vpc: 10,
                            subnet: 10,
                            sg: .2
                        },
                        vol: {
                            i: 5
                        },
                        elb: {
                            i: 5,
                            vpc: 5
                        },
                        eni: {
                            vpc: 10,
                            "*": 2
                        },
                        subnet: {
                            vpc: 10
                        },
                        user: {
                            group: 6,
                            policy: 6
                        },
                        group: {
                            policy: 6
                        },
                        "*": {
                            rtb: 2
                        },
                        igw: {
                            "*": 2
                        },
                        rtb: {
                            "*": 2
                        },
                        acl: {
                            vpc: 5
                        }
                    },
                    linkDistance: {
                        vpc: {
                            vpc: function(link) {
                                return 50 * Math.round(Math.log(link.source.block_count))
                            }
                        },
                        i: {
                            vpc: function(link) {
                                var times = 1;
                                return link.target.link_size >= 10 && (times = 1.5), 40 * times * Math.round(Math.log(link.source.block_count))
                            },
                            subnet: function(link) {
                                var times = 1;
                                return link.target.link_size >= 10 && (times = 1.1), 45 * times * Math.round(Math.log(link.source.block_count))
                            }
                        },
                        vol: {
                            "*": function(link) {
                                return 40
                            }
                        },
                        elb: {
                            "*": function(link) {
                                return 80
                            }
                        },
                        eni: {
                            "*": function(link) {
                                return 40
                            },
                            vpc: function(link) {
                                return 50 * Math.round(Math.log(link.source.block_count))
                            }
                        },
                        subnet: {
                            vpc: function(link) {
                                return 50 * Math.round(Math.log(link.source.block_count))
                            }
                        },
                        "*": {
                            policy: function(link) {
                                return 40
                            },
                            group: function(link) {
                                var times = 1;
                                return link.target.link_size >= 10 && (times = 1.5), 40 * times * Math.round(Math.log(link.source.block_count))
                            },
                            rtb: function(link) {
                                return 40
                            },
                            "*": function(link) {
                                return 40 * Math.round(Math.log(link.source.block_count))
                            }
                        },
                        sg: {
                            vpc: function(link) {
                                return 1 === link.source.link_size ? 80 * Math.round(Math.log(link.source.block_count)) : 20 * Math.round(Math.log(link.source.block_count))
                            }
                        },
                        igw: {
                            "*": function(link) {
                                return 40
                            }
                        },
                        rtb: {
                            "*": function(link) {
                                return 40
                            }
                        },
                        acl: {
                            vpc: function(link) {
                                return 40
                            }
                        }
                    },
                    chargeCompute: function(node) {
                        return "group" === node.type ? -2e3 : "vpc" === node.type ? node.link_size <= 5 ? -3500 : Math.min(-100 * node.link_size, -3e3) : "i" === node.type || "vol" === node.type || "sg" === node.type || "eni" === node.type ? Math.min(-4e3 / Math.sqrt(node.block_count), -400) : -1200
                    }
                }
            },
            nodeData: {}
        }
        var billing_type_url = splunkd_utils.fullpath("saas-aws/splunk_app_aws_billing_report_type", {
            app: utils.getPageInfo().app,
            sharing: "app"
            });
        var billing_type;
        $.get(billing_type_url + "?output_mode=json").done(function(data) {
        billing_type = data.entry[0].content.billing_type;
            
        if(billing_type == "Billing_CUR")
            {
                topology_config_details.detailsPanelConfig.billingQuery.i='`aws-billing-details-cur("*")` InvoiceId=* ResourceId="{0}" | timechart span=1d sum(BlendedCost) as Cost | eval Cost=round(Cost, 2)';
                topology_config_details.detailsPanelConfig.billingQuery.vol='`aws-billing-details-cur("*")` InvoiceId=* ResourceId="{0}" | timechart span=1d sum(BlendedCost) as Cost | eval Cost=round(Cost, 2)';
                topology_config_details.topologyChartConfig.warningMessage.no_billing_data = 'There is no Billing data for EC2. Please check your Billing input configuration, and verify that the saved search "Billing CUR: Topology Billing Metric Generator" is scheduled and enabled.';
            }
        });	

    if (utils.getPageInfo().root) {
        root = `${root}/${utils.getPageInfo().root}`;
    }
    
    return topology_config_details;
    
});
