import json
import copy
import re
import app_aws_bin.utils.app_util as util

logger = util.get_logger()

calc_field_template = {
    "outputFields": [
        {
            # "fieldName": "Name",
            # "owner": "detailed_billing",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": False,
            "editable": True,
            # "displayName": "Name",
            "comment": ""
        }
    ],
    "inputField": "_raw",
    # "owner": "detailed_billing",
    "editable": True,
    "comment": "",
    "calculationType": "Rex",
    # "expression": "user:Name=(?<Name>.*?),"
}

field_template = {
    # "fieldName": "ResourceId",
    # "owner": "instance_hour",
    # "type": "string",
    "fieldSearch": "",
    "required": False,
    "multivalue": False,
    "hidden": False,
    "editable": True,
    # "displayName": "ResourceId",
    "comment": ""
}

account_id_field = {
    "outputFields": [
        {
            "fieldName": "LinkedAccountId",
            # "owner": "instance_hour",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": False,
            "editable": True,
            "displayName": "LinkedAccountId",
            "comment": ""
        }
    ],
    # "owner": "instance_hour",
    "editable": True,
    "comment": "",
    "calculationType": "Eval",
    "expression": "if(isnull(LinkedAccountId), PayerAccountId, LinkedAccountId)"
}

assembly_id_field = {
    "outputFields": [
        {
            "fieldName": "AssemblyId",
            # "owner": "detailed_billing_cur",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": False,
            "editable": True,
            "displayName": "AssemblyId",
            "comment": ""
        }
    ],
    "inputField": "source",
    # "owner": "detailed_billing_cur",
    "editable": True,
    "comment": "",
    "calculationType": "Rex",
    "expression": "\\d{8}-\\d{8}\\/(?<AssemblyId>.*)\\/"
}

account_id_field_cur = {
    "outputFields": [
        {
            "fieldName": "LinkedAccountId",
            # "owner": "instance_hour",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": False,
            "editable": True,
            "displayName": "LinkedAccountId",
            "comment": ""
        }
    ],
    # "owner": "instance_hour",
    "editable": True,
    "comment": "",
    "calculationType": "Eval",
    "expression": "if(isnull(UsageAccountId), PayerAccountId, UsageAccountId)"
}

invoice_id_template = {
    "fieldName": "InvoiceID",
    "owner": "detailed_billing",
    "type": "string",
    "fieldSearch": "",
    "required": False,
    "multivalue": False,
    "hidden": False,
    "editable": True,
    "displayName": "InvoiceID",
    "comment": ""
}

ri_field_1 = {
    "outputFields": [
        {
            "fieldName": "tenancy1",
            "owner": "instance_hour",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": True,
            "editable": True,
            "displayName": "tenancy1",
            "comment": ""
        },
        {
            "fieldName": "platform1",
            "owner": "instance_hour",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": True,
            "editable": True,
            "displayName": "platform1",
            "comment": ""
        },
        {
            "fieldName": "instance_type1",
            "owner": "instance_hour",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": True,
            "editable": True,
            "displayName": "instance_type1",
            "comment": ""
        }
    ],
    "inputField": "ItemDescription",
    "owner": "instance_hour",
    "editable": True,
    "comment": "",
    "calculationType": "Rex",
    "expression": ".* per (?<tenancy1>(Dedicated|On Demand|Spot)?)\\s*(Usage|hour for)?\\s*(?<platform1>(Red Hat|Windows BYOL|SQL \\w+|Windows with SQL \\w+|[\\w\\/]+)).*?(?<instance_type1>[\\w.\\d]+)( [iI]nstance.*|$)"
}

ri_field_1_cur = {
    "outputFields": [
        {
            "fieldName": "tenancy1",
            "owner": "instance_hour_cur",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": True,
            "editable": True,
            "displayName": "tenancy1",
            "comment": ""
        },
        {
            "fieldName": "platform1",
            "owner": "instance_hour_cur",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": True,
            "editable": True,
            "displayName": "platform1",
            "comment": ""
        },
        {
            "fieldName": "instance_type1",
            "owner": "instance_hour_cur",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": True,
            "editable": True,
            "displayName": "instance_type1",
            "comment": ""
        }
    ],
    "inputField": "LineItemDescription",
    "owner": "instance_hour_cur",
    "editable": True,
    "comment": "",
    "calculationType": "Rex",
    "expression": ".* per (?<tenancy1>(Dedicated|On Demand|Spot)?)\\s*(Usage|hour for)?\\s*(?<platform1>(Red Hat|Windows BYOL|SQL \\w+|Windows with SQL \\w+|[\\w\\/]+)).*?(?<instance_type1>[\\w.\\d]+)( [iI]nstance.*|$)"
}

ri_field_2 = {
    "outputFields": [
        {
            "fieldName": "instance_type2",
            "owner": "instance_hour",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": True,
            "editable": True,
            "displayName": "instance_type2",
            "comment": ""
        },
        {
            "fieldName": "platform2",
            "owner": "instance_hour",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": True,
            "editable": True,
            "displayName": "platform2",
            "comment": ""
        },
        {
            "fieldName": "tenancy2",
            "owner": "instance_hour",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": True,
            "editable": True,
            "displayName": "tenancy2",
            "comment": ""
        }
    ],
    "inputField": "ItemDescription",
    "owner": "instance_hour",
    "editable": True,
    "comment": "",
    "calculationType": "Rex",
    "expression": "(?<instance_type2>[\\w.\\d]+)\\s+(?<platform2>(Red Hat|Windows BYOL|SQL \\w+|Windows with SQL \\w+|[\\w\\/]+))\\s(?<tenancy2>(Dedicated|On Demand|Spot)?)\\sInstance-hour.*"
}

ri_field_2_cur = {
    "outputFields": [
        {
            "fieldName": "instance_type2",
            "owner": "instance_hour_cur",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": True,
            "editable": True,
            "displayName": "instance_type2",
            "comment": ""
        },
        {
            "fieldName": "platform2",
            "owner": "instance_hour_cur",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": True,
            "editable": True,
            "displayName": "platform2",
            "comment": ""
        },
        {
            "fieldName": "tenancy2",
            "owner": "instance_hour_cur",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": True,
            "editable": True,
            "displayName": "tenancy2",
            "comment": ""
        }
    ],
    "inputField": "LineItemDescription",
    "owner": "instance_hour_cur",
    "editable": True,
    "comment": "",
    "calculationType": "Rex",
    "expression": "(?<instance_type2>[\\w.\\d]+)\\s+(?<platform2>(Red Hat|Windows BYOL|SQL \\w+|Windows with SQL \\w+|[\\w\\/]+))\\s(?<tenancy2>(Dedicated|On Demand|Spot)?)\\sInstance-hour.*"
}

ri_field_rfield_cur = {
    "outputFields": [
        {
            "fieldName": "rplatform",
            "owner": "instance_hour_cur",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": False,
            "editable": True,
            "displayName": "rplatform",
            "comment": ""
        },
        {
            "fieldName": "rinstancetype",
            "owner": "instance_hour_cur",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": False,
            "editable": True,
            "displayName": "rinstancetype",
            "comment": ""
        }
    ],
    "inputField": "LineItemDescription",
    "owner": "instance_hour_cur",
    "editable": True,
    "comment": "",
    "calculationType": "Rex",
    "expression": "(?<rplatform>(?:Red Hat|Windows BYOL|SQL \\w+|Windows with SQL \\w+|[\\w\\/]+)).*?(?<rinstancetype>[\\w.\\d]+?)(?:\\s[rR]eserved)"
}

ri_field_rtenancy = {
    "outputFields": [
        {
            "fieldName": "rtenancy",
            "owner": "instance_hour_cur",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": False,
            "editable": True,
            "displayName": "rtenancy",
            "comment": ""
        }
    ],
    "owner": "instance_hour_cur",
    "editable": True,
    "comment": "",
    "calculationType": "Eval",
    "expression": "if(term == \"OnDemand\" OR term == \"\" OR isnull(term), \"On Demand\", term)"
}

ri_filed_reservedinstance = {
    "outputFields": [
        {
            "fieldName": "ReservedInstance",
            "owner": "instance_hour_cur",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": False,
            "editable": True,
            "displayName": "ReservedInstance",
            "comment": ""
        }
    ],
    "owner": "instance_hour_cur",
    "editable": True,
    "comment": "",
    "calculationType": "Eval",
    "expression": "if(term == \"Reserved\", \"Y\", \"N\")"
}

ri_field_platform_3 = {
    "outputFields": [
        {
            "fieldName": "platform3",
            "owner": "instance_hour",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": True,
            "editable": True,
            "displayName": "platform3",
            "comment": ""
        }
    ],
    "owner": "instance_hour",
    "editable": True,
    "comment": "",
    "calculationType": "Eval",
    "expression": "if(isnull(platform1), platform2, platform1)"
}

ri_field_platform_3_cur = {
    "outputFields": [
        {
            "fieldName": "platform3",
            "owner": "instance_hour_cur",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": True,
            "editable": True,
            "displayName": "platform3",
            "comment": ""
        }
    ],
    "owner": "instance_hour_cur",
    "editable": True,
    "comment": "",
    "calculationType": "Eval",
    "expression": "coalesce(platform1,platform2,rplatform)"
}

ri_field_tenancy = {
    "outputFields": [
        {
            "fieldName": "tenancy",
            "owner": "instance_hour",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": False,
            "editable": True,
            "displayName": "Tenancy",
            "comment": ""
        }
    ],
    "owner": "instance_hour",
    "editable": True,
    "comment": "",
    "calculationType": "Eval",
    "expression": "case((tenancy1 == \"\" OR isnull(tenancy1)) AND (tenancy2 == \"\" OR isnull(tenancy2)), \"On Demand\", tenancy1 == \"\" OR isnull(tenancy1),tenancy2,(tenancy2 == \"\" OR isnull(tenancy2)), tenancy1)"
}

ri_field_tenancy_cur = {
    "outputFields": [
        {
            "fieldName": "tenancy",
            "owner": "instance_hour_cur",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": False,
            "editable": True,
            "displayName": "Tenancy",
            "comment": ""
        }
    ],
    "owner": "instance_hour_cur",
    "editable": True,
    "comment": "",
    "calculationType": "Eval",
    "expression": "coalesce(tenancy3,tenancy2,rtenancy)"
}

ri_field_instance_type = {
    "outputFields": [
        {
            "fieldName": "instance_type",
            "owner": "instance_hour",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": False,
            "editable": True,
            "displayName": "InstanceType",
            "comment": ""
        }
    ],
    "owner": "instance_hour",
    "editable": True,
    "comment": "",
    "calculationType": "Eval",
    "expression": "if((isnull(instance_type1) OR instance_type1 == \"\"), instance_type2, instance_type1)"
}

ri_field_instance_type_cur = {
    "outputFields": [
        {
            "fieldName": "instance_type",
            "owner": "instance_hour_cur",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": False,
            "editable": True,
            "displayName": "InstanceType",
            "comment": ""
        }
    ],
    "owner": "instance_hour_cur",
    "editable": True,
    "comment": "",
    "calculationType": "Eval",
    "expression": "coalesce(instance_type1,instance_type2,rinstancetype)"
}

ri_field_platform = {
    "outputFields": [
        {
            "fieldName": "platform",
            "owner": "instance_hour",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": False,
            "editable": True,
            "displayName": "Platform",
            "comment": ""
        }
    ],
    "owner": "instance_hour",
    "editable": True,
    "comment": "",
    "calculationType": "Eval",
    "expression": "case(platform3 == \"Linux/UNIX\", \"Linux\", platform3 == \"Red Hat\", \"RHEL\", platform3 == \"SQL Std\", \"Windows with SQL Std\", platform3 == \"SQL Web\", \"Windows with SQL Web\", true(), platform3)"
}

ri_field_platform_cur = {
    "outputFields": [
        {
            "fieldName": "platform",
            "owner": "instance_hour_cur",
            "type": "string",
            "fieldSearch": "",
            "required": False,
            "multivalue": False,
            "hidden": False,
            "editable": True,
            "displayName": "Platform",
            "comment": ""
        }
    ],
    "owner": "instance_hour_cur",
    "editable": True,
    "comment": "",
    "calculationType": "Eval",
    "expression": "case(platform3 == \"Linux/UNIX\", \"Linux\", platform3 == \"Red Hat\", \"RHEL\", platform3 == \"SQL Std\", \"Windows with SQL Std\", platform3 == \"SQL Web\", \"Windows with SQL Web\", true(), platform3)"
}

DEFAULT_TAGS = ['instance_type', 'tenancy', 'platform', 'LinkedAccountId']

FIELD_PREFIX = 'AWSTAG'


def upgrade_421(description):
    logger.info('upgrading datamodel to 4.2.1')
    json_description = json.loads(description)
    search = json_description['objects'][0]['constraints'][0]['search']
    if not 'RecordType' in search:
        logger.info('RecordType not found. Upgrading search field(%s)...' % search)
        search += ' RecordType!=\"*Total\"'
        json_description['objects'][0]['constraints'][0]['search'] = search
        logger.info('After upgrading... search field(%s)' % search)

        return json.dumps(json_description)
    else:
        logger.info('no need to upgrade to 4.2.1')
        return description

def upgrade_500(description):
    logger.info('upgrading datamodel to 5.0.0')
    json_description = json.loads(description)
    fields = json_description['objects'][0]['fields']

    invoice_field = [field for field in fields if field['fieldName'] == 'InvoiceID']

    if not invoice_field:
        logger.info('InvoiceID not found. Upgrading fields...')
        fields.append(invoice_id_template)
        json_description['objects'][0]['fields'] = fields
        logger.info('After upgrading... Fields(%s)' % fields)

        return json.dumps(json_description)
    else:
        logger.info('no need to upgrade to 5.0.0')
        return description

def upgrade_510(description):
    logger.info('upgrading detailed_billing datamodel to 5.1.0')
    json_description = json.loads(description)

    fields = json_description['objects'][0]['fields']

    # 1. add S3KeyLastModified
    s3key = [field for field in fields if field['fieldName'] == 'S3KeyLastModified']
    if not s3key:
        logger.info('S3KeyLastModified not found. Upgrading fields...')
        fields.append(generate_field('detailed_billing', 'S3KeyLastModified', 'S3KeyLastModified', 'string'))
        json_description['objects'][0]['fields'] = fields

        return json.dumps(json_description)
    else:
        logger.info('no need to upgrade detailed_billing to 5.1.0')
        return description


def instance_hour_upgrade_510(description):
    logger.info('upgrading instance_hour datamodel to 5.1.0')
    json_description = json.loads(description)

    fields = json_description['objects'][0]['fields']
    calculations = json_description['objects'][0]['calculations']
    changed = False


    # upgrade fields
    # 1. add ItemDescription
    item_description = [field for field in fields if field['fieldName'] == 'ItemDescription']
    if not item_description:
        logger.info('ItemDescription not found. Upgrading fields...')
        changed = True
        fields.append(generate_field('instance_hour', 'ItemDescription', 'ItemDescription', 'string'))

    # 2. add ResourceId
    resource_id = [field for field in fields if field['fieldName'] == 'ResourceId']
    if not resource_id:
        logger.info('ResourceId not found. Upgrading fields...')
        changed = True
        fields.append(generate_field('instance_hour', 'ResourceId', 'ResourceId', 'string'))

    # 3. add S3KeyLastModified
    s3key = [field for field in fields if field['fieldName'] == 'S3KeyLastModified']
    if not s3key:
        logger.info('S3KeyLastModified not found. Upgrading fields...')
        changed = True
        fields.append(generate_field('instance_hour', 'S3KeyLastModified', 'S3KeyLastModified', 'string'))

    # 4. remove UsageType
    usage_type = [field for field in fields if field['fieldName'] == 'UsageType']
    if usage_type:
        logger.info('Found UsageType. Upgrading fields...')
        changed = True
        fields = [x for x in fields if x['fieldName'] != 'UsageType']


    # upgrade calculations
    # 5. remove instance_type
    instance_type = [field for field in calculations if 'inputField' in field and field['inputField'] == 'UsageType']
    if instance_type:
        logger.info('Found UsageType. Upgrading calculations...')
        changed = True
        calculations = [x for x in calculations if not 'inputField' in x or x['inputField'] != 'UsageType']

    # 6. add ri field
    tenancy = [field for field in calculations if field['outputFields'][0]['fieldName'] == 'tenancy']

    if len(tenancy) == 0:
        logger.info('RI fields not found. Upgrading calculations...')
        changed = True
        calculations.append(ri_field_1)
        calculations.append(ri_field_2)
        calculations.append(ri_field_platform_3)
        calculations.append(ri_field_platform)
        calculations.append(ri_field_instance_type)
        calculations.append(ri_field_tenancy)

    # 7. update constraints
    search = json_description['objects'][0]['constraints'][0]['search']
    if 'UsageQuantity' in search:
        logger.info('Found UsageQuantity. Upgrading search field(%s)...' % search)
        changed = True
        search = "`aws-billing-details(\"*\")`\n ProductName=\"Amazon Elastic Compute Cloud\" Operation=\"RunInstances*\" UsageType=*Usage* UsageType!=\"*Host*Usage*\""

    if changed:
        json_description['objects'][0]['fields'] = fields
        json_description['objects'][0]['calculations'] = calculations
        json_description['objects'][0]['constraints'][0]['search'] = search
        return json.dumps(json_description)
    else:
        logger.info('no need to upgrade instance_hour to 5.1.0')
        return description


# For the schema of modelEntity, refer to http://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTknowledge#datamodel.2Fmodel.2F.7Bname.7D
def update_description(description, tags):
    json_description = json.loads(description)
    model_name = json_description['modelName']
    calculations = []

    model_name = model_name.lower()

    # Append pre-built fields (tenancy, platform, instance_type) for instance_hour
    if model_name == 'instance_hour':
        calculations.append(ri_field_1)
        calculations.append(ri_field_2)
        calculations.append(ri_field_platform_3)
        calculations.append(ri_field_platform)
        calculations.append(ri_field_instance_type)
        calculations.append(ri_field_tenancy)
    
    if model_name == 'instance_hour_cur' or model_name == "detailed_billing_cur":
        # Append pre-built field LinkedAccountId, Assembly for both detailed_billing_cur and instance_hour_cur
        assembly_id_dict = copy.deepcopy(account_id_field_cur)
        assembly_id_dict['outputFields'][0]['owner'] = model_name
        assembly_id_dict['owner'] = model_name
        calculations.append(assembly_id_dict)
        
        assembly_id_dict = copy.deepcopy(assembly_id_field)
        assembly_id_dict['outputFields'][0]['owner'] = model_name
        assembly_id_dict['owner'] = model_name
        calculations.append(assembly_id_dict)
    
    # Append pre-built fields (tenancy, platform, instance_type) for instance_hour
    if model_name == 'instance_hour_cur':
        calculations.append(ri_field_1_cur)
        calculations.append(ri_field_2_cur)
        calculations.append(ri_field_rfield_cur)
        calculations.append(ri_field_rtenancy)
        calculations.append(ri_field_platform_3_cur)
        calculations.append(ri_field_tenancy_cur)
        calculations.append(ri_field_instance_type_cur)
        calculations.append(ri_field_platform_cur)
        calculations.append(ri_filed_reservedinstance)
    
    if model_name == 'instance_hour' or model_name == "detailed_billing":
        # Append pre-built field LinkedAccountId for both detailed_billing and instance_hour
        account_id_dict = copy.deepcopy(account_id_field)
        account_id_dict['outputFields'][0]['owner'] = model_name
        account_id_dict['owner'] = model_name
        calculations.append(account_id_dict)
    
    

    all_tags = []
    uniq_id = 0
    for tag in tags:
        if tag in DEFAULT_TAGS:
            continue

        (field_name, uniq_id) = generate_field_name(tag, uniq_id, all_tags)

        if field_name is None:
            continue

        all_tags.append(field_name)

        calc_field = generate_calc_field(model_name, field_name, tag)
        calculations.append(calc_field)
        logger.info('added tag: %s for %s, display name: %s' % (field_name, model_name, tag))

    json_description['objects'][0]['calculations'] = calculations

    return json.dumps(json_description)


# the field_name does not support most special characters
# the length of field_name has to be <= 32 characters
def generate_field_name(tag, uniq_id, all_tags):
    field_name = re.sub('[^a-zA-Z0-9]', '_', tag)

    # The field_name cannot start with _ or digit. It is a limitation of Splunk or Regex
    if field_name.startswith('_') or field_name[0].isdigit():
        new_field_name = FIELD_PREFIX + field_name
        logger.warning('tag %s has a wrong field name %s, replace it with %s' % (tag, field_name, new_field_name))
        field_name = new_field_name

    if len(field_name) >= 32:
        field_name = field_name[0:30]

    base_field_name = field_name
    while field_name in DEFAULT_TAGS or field_name in all_tags:
        if uniq_id > 99:
            break

        field_name = '%s%02d' % (base_field_name , uniq_id)
        uniq_id += 1

        logger.warning('Tag %s already exists, replaced it with %s.' % (tag, field_name))

    return (field_name, uniq_id)

def generate_field(model_name, field_name, display_name, field_type):
    field = copy.deepcopy(field_template)
    field['fieldName'] = field_name
    field['owner'] = model_name
    field['type'] = field_type
    field['displayName'] = display_name

    return field


def generate_calc_field(model_name, field_name, display_name):
    calc_field = copy.deepcopy(calc_field_template)
    calc_field['outputFields'][0]['owner'] = model_name
    calc_field['outputFields'][0]['fieldName'] = field_name
    calc_field['outputFields'][0]['displayName'] = display_name
    calc_field['owner'] = model_name
    calc_field['expression'] = 'user:%s=((?!\")|(\"))(?<%s>.*?)((?!\")|(\")),' % (display_name, field_name)

    return calc_field

