import json
import splunk.rest as rest
import splunk.entity as entity
import splunk.Intersplunk as intersplunk
import app_aws_bin.utils.app_util as util

logger = util.get_logger()
app_name = "splunk_app_aws"
owner = 'nobody'
CONF_WEB = 'configs/conf-web'
billing_collection_name = "billingReportType_kvstore"
url = "https://{}/servicesNS/nobody/splunk_app_aws/{}?output_mode=json"

def getkvstorestatus(session_key):
    '''
        Get the status of KV Store 
    '''
    logger.info("Getting the KV Store Status")
    response, content = rest.simpleRequest(
        "/services/kvstore/status",
        sessionKey=session_key,
        method='GET',
        raiseAllErrors=True,
        getargs={"output_mode": "json"}
    )
    data = json.loads(content)
    return data["entry"][0]["content"]["current"]["status"]


def getsessionkey():
    '''
        Get the Session Key
    '''
    results, dummyresults, settings = intersplunk.getOrganizedResults()
    session_key = settings['sessionKey']
    return session_key


def delete_data(delete_url, session_key):
    '''
        Delete the data of lookup
    '''
    logger.info("Deleting the data of Lookup")
    response, content = rest.simpleRequest(
            delete_url,
            sessionKey=session_key,
            method='DELETE',
            raiseAllErrors=True
        )
    if response['status'] == "200":
        return True
    else:

        return False


def insert_in_lookup(insert_url, source_data, session_key):
    '''
        Insert the data to lookup with the changed key exclude_list
    '''
    logger.info("Inserting the data in Lookup")
    insert_data = {}
    insert_data["username"] = source_data[0]["username"]
    insert_data["exclude_list"] = source_data[0]["blacklist"]
    insert_data["_user"] = source_data[0]["_user"]
    insert_data["_key"] = source_data[0]["_key"]
    payload = json.dumps(insert_data)
    response, content = rest.simpleRequest(
            insert_url,
            sessionKey=session_key,
            jsonargs=payload,
            method='POST',
            raiseAllErrors=True
        )
    if response['status'] == "201":
        return True
    else:
        return False


def updatekvstore(splunkd_uri, session_key):
    '''
        Update the KV Store
    '''
    access_collection_url = url.format(
            splunkd_uri,
            "storage/collections/data/"+billing_collection_name
        )
    logger.info("Getting the data from old Lookup")
    response, content = rest.simpleRequest(
            access_collection_url,
            sessionKey=session_key,
            method='GET',
            raiseAllErrors=True
        )
    content = content.decode('utf-8')
    source_data = json.loads(content)
    if len(source_data) > 0:
        post_data = json.dumps(source_data[0])
        if "blacklist" in source_data[0]:
            deleted = delete_data(access_collection_url, session_key)
            if deleted:
                logger.info("Deleted the old data from billingReportType_kvstore Lookup")
                insert = insert_in_lookup(
                    access_collection_url, source_data, session_key
                )
                if insert:
                    logger.info("Inserted the new data in billingReportType_kvstore Lookup")
                    return "Update of KV Store billingReportType_kvstore complete!!"
                else:
                    # insert the source data again in kvstore 
                    response, con = rest.simpleRequest(
                        access_collection_url,
                        sessionKey=session_key, 
                        jsonargs=post_data,
                        method='POST',
                        raiseAllErrors=True
                        )
                    logger.error("Failed to insert new data so inserting the old data again in billingReportType_kvstore Lookup")
                    return "Failed to update billingReportType_kvstore " 
            else:
                logger.error("Failed to update billingReportType_kvstore. Error in deleting older data from lookup.")
                return "Failed to update billingReportType_kvstore "
        else:
            logger.info("The billingReportType_kvstore is already updated.")
            return "billingReportType_kvstore already updated !!"
    else:
        logger.info("There is not data to be updated in billingReportType_kvstore KV Store")
        return "No data in billingReportType_kvstore to be updated !!"


def main():
    try:
        logger.info("Started updating KV Store billingReportType_kvstore")
        results = []
        session_key = getsessionkey()
        status = getkvstorestatus(session_key)
        if status == "ready":
            splunkd_uri = entity.getEntity(
                        CONF_WEB,
                        'settings',
                        sessionKey=session_key,
                        namespace=app_name,
                        owner=owner
                    ).get('mgmtHostPort', '127.0.0.1:8089')
                        
            update = updatekvstore(splunkd_uri, session_key)
            result = {
                'Task': 'Sync KVStore',
                'Result': update}
        else:
            result = {
                'Task': 'Sync KVStore',
                'Result': 'KV Store is not in ready state. Make sure it is enabled.'}
        results.append(result)
    except Exception:
        import traceback
        stack = traceback.format_exc()
        logger.error(str(stack))
        results = intersplunk.generateErrorResults(
                "Something went wrong. Try again later\n Error : Traceback: " + str(stack)
                )

    intersplunk.outputResults(results)


if __name__ == "__main__":
    main()
