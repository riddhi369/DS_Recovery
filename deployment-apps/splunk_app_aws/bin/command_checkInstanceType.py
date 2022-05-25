import json
import splunk.rest as rest
import splunk.entity as entity
import splunk.Intersplunk as intersplunk
import logging
from dao.kvstore_access_object import KVStoreAccessObject
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
import os
import xml.etree.ElementTree as ET

instance_url = "https://{}/services/server/info/server-info?output_mode=json"
INSTANCE_KVSTORE_NAMESPACE = "aws_instance_type_kvstore"
BILLING_KVSTORE_NAMESPACE = "billingReportType_kvstore"
logging.basicConfig(
    filename=make_splunkhome_path(["var", "log", "splunk"])
    + "/splunk_app_aws_ec2_deprecation.log",
    format="%(asctime)s %(levelname)s %(lineno)d %(message)s",
    filemode="a+",
)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

view_map = {
    "budget_planner": "budget_planner_cur",
    "estimated_billing": "estimated_billing_cur",
    "monthly_billing": "monthly_billing_cur",
    "detailed_billing": "detailed_billing_cur",
    "capacity_planner": "capacity_planner_cur",
    "RI_planner": "RI_planner_cur",
}


def getsessionkey():
    """
    Get the Session Key
    """
    logger.info("Getting session key")
    results, dummyresults, settings = intersplunk.getOrganizedResults()
    session_key = settings["sessionKey"]
    user = settings["owner"]
    logger.info("Got session key sucessfully")
    return user, session_key


def check_instance_type(splunkd_uri, user, session_key):
    check_instance_url = instance_url.format(splunkd_uri)
    response, content = rest.simpleRequest(
        check_instance_url,
        sessionKey=session_key,
        method="GET",
        raiseAllErrors=True,
    )
    if response.status == 200:
        data = json.loads(content)
        instance_type = data["entry"][0]["content"].get("instance_type")
        if instance_type == None:
            logger.info(
                "instance_type key does not exists in server. Setting instance_type as on-prem"
            )
            instance_type = "on-prem"
        else:
            logger.info(
                "instance_type key exists in server. Setting instance_type as cloud"
            )
        instance_kao = KVStoreAccessObject(
            INSTANCE_KVSTORE_NAMESPACE, session_key
        )
        instance_kao.insert_single_item(
            {"_key": "instance_type", "value": instance_type}
        )
        return instance_type


def add_menu(instance_type, user, session_key):
    nav_path_default = make_splunkhome_path(
        ["etc", "apps", "splunk_app_aws", "default", "data", "ui", "nav"]
    )
    nav_path_local = make_splunkhome_path(
        ["etc", "apps", "splunk_app_aws", "local", "data", "ui", "nav"]
    )
    if not os.path.exists(nav_path_local):
        os.makedirs(nav_path_local)

    billing = KVStoreAccessObject(BILLING_KVSTORE_NAMESPACE, session_key)
    reportType = billing.query_items({"username": user})
    reportType = json.loads(reportType)
    if len(reportType) > 0:
        try:
            reportType = reportType[0]["exclude_list"][0]
        except KeyError:
            reportType = reportType[0]["blacklist"][0]
    else:
        reportType = "Billing"
    logger.info("Billing report type is " + reportType)
    tree = ET.parse(os.path.join(nav_path_default, "default.xml"))
    # get root element
    root = tree.getroot()
    if reportType == "Billing_CUR":
        billing_coll = root.find("./collection/[@label='Billing']")
        for child in billing_coll:
            if child.attrib["name"] in list(view_map.keys()):
                child.attrib["name"] = view_map[child.attrib["name"]]
        usage_col = root.find("./collection/[@label='Usage']")
        for child in usage_col:
            # checks if the attribute exists and only then replaces
            if "name" in child.attrib and child.attrib["name"] in list(
                view_map.keys()
            ):
                child.attrib["name"] = view_map[child.attrib["name"]]

    if instance_type != "cloud":
        insights_coll = root.find("./collection/[@label='Insights']")
        new_element = ET.Element('view name="ec2_insights"')
        insights_coll.insert(3, new_element)

    else:
        logger.info(
            "Instance Type is Cloud. No need to update Insights Navigation menu"
        )

    XMLString = ET.tostring(root, method="xml").decode()
    logger.info("Updated navigation menu is " + XMLString)
    response = rest.simpleRequest(
        "/servicesNS/nobody/splunk_app_aws/data/ui/nav/default",
        sessionKey=session_key,
        method="POST",
        postargs={"eai:data": XMLString},
    )
    logger.info(response)
    if response[0]["status"] == "200":
        # Refresh the nav endpoint so that our changes take effect
        nav_entity = entity.getEntities(
            "data/ui/nav/_reload",
            sessionKey=session_key,
            namespace="splunk_app_aws",
            owner="nobody",
        )
        logger.info("Successfully updated navigation menu")
    else:
        logger.error(
            "Encounter some error while updating navigation menu. \n Error:{}".format(
                response
            )
        )


def main():
    app_name = "splunk_app_aws"
    owner = "nobody"
    CONF_WEB = "configs/conf-web"
    try:
        logger.info(
            "Started updating navigation menu as per the Instance type On-prem/Cloud"
        )
        user, session_key = getsessionkey()
        instance_type = KVStoreAccessObject(
            INSTANCE_KVSTORE_NAMESPACE, session_key
        )
        lookup_value = instance_type.query_items({"_key": "instance_type"})
        lookup_value = json.loads(lookup_value)
        if len(lookup_value) != 0:
            logger.info(
                "Exiting script as lookup is already filled with value {}".format(
                    lookup_value
                )
            )
            intersplunk.outputResults([{"value": lookup_value[0]["value"]}])
            exit()
        splunkd_uri = entity.getEntity(
            CONF_WEB,
            "settings",
            sessionKey=session_key,
            namespace=app_name,
            owner=owner,
        ).get("mgmtHostPort", "127.0.0.1:8089")
        instance_type = check_instance_type(splunkd_uri, user, session_key)
        add_menu(instance_type, user, session_key)
        intersplunk.outputResults([{"value": instance_type}])

    except Exception as e:
        import traceback

        stack = traceback.format_exc()
        logger.error(str(stack))
        errorMsg = intersplunk.generateErrorResults(
            "Something went wrong. Try again later\n Error : Traceback: "
            + str(stack)
        )
        intersplunk.outputResults(errorMsg)


if __name__ == "__main__":
    main()