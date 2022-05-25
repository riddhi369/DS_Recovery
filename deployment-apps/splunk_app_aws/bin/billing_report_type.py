import json
import os
import splunk.rest as Rest
import xml.etree.ElementTree as ET
import splunk.admin as admin 
from app_aws_bin.utils.local_manager import LocalServiceManager 
from splunklib.client import Entity
import splunk.entity as en 
from dao.kvstore_access_object import KVStoreAccessObject 
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path 
import app_aws_bin.utils.app_util as util

DEFAULT_OWNER = 'nobody'

ARG_BILLING_REPORT = 'billing_type'

KVSTORE_NAMESPACE = 'billingReportType_kvstore'

PAGE_ROOT_MAP = {
    'Billing': ['estimated_billing', 'monthly_billing', 'detailed_billing', 'budget_planner', 'capacity_planner', 'RI_planner', 'RI_planner_detail'],
	'Billing_CUR': ['estimated_billing_cur', 'monthly_billing_cur', 'detailed_billing_cur', 'budget_planner_cur', 'capacity_planner_cur', 'RI_planner_cur', 'RI_planner_detail_cur']
}


class BillingReportType(admin.MConfigHandler):
    def __init__(self, scriptMode, ctxInfo):
        admin.MConfigHandler.__init__(self, scriptMode, ctxInfo)
        session_key = self.getSessionKey()
        service = LocalServiceManager(
            util.APP_NAME, DEFAULT_OWNER, session_key).get_local_service()
        self.username = Entity(
            service, 'authentication/current-context').content['username']
        self.kao = KVStoreAccessObject(KVSTORE_NAMESPACE, session_key)
        self.existed_exclude_list = json.loads(
            self.kao.query_items({'username': self.username}))

    def setup(self):
        for arg in [ARG_BILLING_REPORT]:
            self.supportedArgs.addOptArg(arg)

    def handleRemove(self, confInfo):
        bill_remove = self.callerArgs.id
        bill_report_remove = None
        for root in PAGE_ROOT_MAP:
            if bill_remove in PAGE_ROOT_MAP[root]:
                bill_report_remove = root
                break

        if bill_report_remove is None:
            return

        # if not exist, insert directly
        if len(self.existed_exclude_list) == 0:
            self.kao.insert_single_item({
                'username': self.username,
                'exclude_list': [bill_report_remove]
            })
        # else, update
        else:
            exclude_list = self.existed_exclude_list[0]['exclude_list']
            if bill_report_remove not in exclude_list:
                self.kao.update_item_by_key(self.existed_exclude_list[0]['_key'], {
                    'username': self.username,
                    'exclude_list': exclude_list + [bill_report_remove]
                })
        return

    def handleList(self, confInfo):
        results = confInfo['billing_type']

        billing_type = []

        # search exclude list from kvstore
        self.existed_exclude_list = json.loads(self.kao.query_items({'username': self.username}))
        if len(self.existed_exclude_list) > 0:
            billing_type = self.existed_exclude_list[0]['exclude_list']

        results.append('billing_type', billing_type)
		
        pages = []
        for root in billing_type:
            pages += PAGE_ROOT_MAP[root]

        results.append('pages', pages)
        return

    def handleCreate(self, confInfo):
        if self.callerArgs[ARG_BILLING_REPORT][0] is None:
            page_roots = []
        else:
            page_roots = self.callerArgs[ARG_BILLING_REPORT][0].split(',')
            reportType = str(page_roots[0])

        # if not exist, insert directly
        if len(self.existed_exclude_list) == 0:
            self.kao.insert_single_item({
                'username': self.username,
                'exclude_list': page_roots
            })
        # else, update
        else:
            self.kao.update_item_by_key(self.existed_exclude_list[0]['_key'], {
                'username': self.username,
                'exclude_list': page_roots
            })

        # Reorganizing navigation based on user selection
        nav_path_default = make_splunkhome_path(['etc', 'apps', 'splunk_app_aws', 'default', 'data', 'ui', 'nav'])
        nav_path_local = make_splunkhome_path(['etc', 'apps', 'splunk_app_aws', 'local', 'data', 'ui', 'nav'])

        if not os.path.exists(nav_path_local):
            os.makedirs(nav_path_local)
        
        INSTANCE_KVSTORE_NAMESPACE = "aws_instance_type_kvstore"
        instance_type = KVStoreAccessObject(
            INSTANCE_KVSTORE_NAMESPACE, self.getSessionKey()
        )
        lookup_value = instance_type.query_items({"_key": "instance_type"})
        lookup_value = json.loads(lookup_value)

        tree = ET.parse(os.path.join(nav_path_default, 'default.xml'))
        # get root element
        root = tree.getroot()
        if len(lookup_value) != 0 and lookup_value[0]["value"] == "on-prem":
            insights_coll = root.find("./collection/[@label='Insights']")
            new_element = ET.Element('view name="ec2_insights"')
            insights_coll.insert(3, new_element)
        
        if reportType == "Billing_CUR":
            # view old name => new name map
            view_map = {
                "budget_planner": "budget_planner_cur",
                "estimated_billing": "estimated_billing_cur",
                "monthly_billing": "monthly_billing_cur",
                "detailed_billing": "detailed_billing_cur",
                "capacity_planner": "capacity_planner_cur",
                "RI_planner": "RI_planner_cur"
            }

            # find collection with label="Billing"
            billing_coll = root.find("./collection/[@label='Billing']")
            for child in billing_coll:
                if child.attrib["name"] in list(view_map.keys()):
                    child.attrib["name"] = view_map[child.attrib["name"]]

            # find collection with label="Usage"
            usage_col = root.find("./collection/[@label='Usage']")
            for child in usage_col:
                # checks if the attribute exists and only then replaces
                if 'name' in child.attrib and child.attrib["name"] in list(view_map.keys()):
                    child.attrib["name"] = view_map[child.attrib["name"]]

        
        XMLString = ET.tostring(root, method='xml').decode()
        response = Rest.simpleRequest("/servicesNS/nobody/splunk_app_aws/data/ui/nav/default", sessionKey= self.getSessionKey(), method='POST', postargs={'eai:data': XMLString})

        # Refresh the nav endpoint so that our changes take effect
        nav_entity = en.getEntities('data/ui/nav/_reload', sessionKey = self.getSessionKey(), namespace='splunk_app_aws', owner='nobody')
        
        return

admin.init(BillingReportType, admin.CONTEXT_APP_ONLY)
