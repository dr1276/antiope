
import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

import json
import os
import time
from dateutil import tz
import hashlib


from lib.account import *
from lib.common import *

import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)

RESOURCE_PATH = "inspector/finding"
RESOURCE_TYPE = "AWS::Inspector::Finding"


def lambda_handler(event, context):
    logger.debug("Received event: " + json.dumps(event, sort_keys=True))
    message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info("Received message: " + json.dumps(message, sort_keys=True))

    try:
        target_account = AWSAccount(message['account_id'])
        for r in target_account.get_regions():
            try:
                client = target_account.get_client('inspector', region=r)
                assessment_arn = get_most_recent_assessment_run(client, target_account)
                if assessment_arn is None:
                    continue   # Next region
                findings = get_findings(client, assessment_arn)
                logger.info(f"Got {len(findings)} findings for account {target_account.account_name}({target_account.account_id})")
                assessment_id = assessment_arn.split('/')[-1] # Grab the string after the last /
                for f in findings:
                    process_finding(f, target_account, r, assessment_id)
            except EndpointConnectionError as e:
                pass  # Do not worry about regions where Inspector doesn't exist.

    except AntiopeAssumeRoleError as e:
        logger.error("Unable to assume role into account {}({})".format(target_account.account_name, target_account.account_id))
        return()
    except ClientError as e:
        logger.critical("AWS Error getting info for {}: {}".format(message['account_id'], e))
        capture_error(message, context, e, "ClientError for {}: {}".format(message['account_id'], e))
        raise
    except Exception as e:
        logger.critical("{}\nMessage: {}\nContext: {}".format(e, message, vars(context)))
        capture_error(message, context, e, "General Exception for {}: {}".format(message['account_id'], e))
        raise


def get_most_recent_assessment_run(client, target_account):
    response = client.list_assessment_runs(filter={
        'completionTimeRange': {
            'beginDate': datetime.datetime.now() - datetime.timedelta(days=7),
            'endDate': datetime.datetime.now()
        }
    } )
    print(response)
    if 'assessmentRunArns' in response and len(response['assessmentRunArns']) > 0:
        if len(response['assessmentRunArns']) > 1:
            logger.error(f"Got back {len(response['assessmentRunArns'])} assessment runs, expected 1: {response}")
        return(response['assessmentRunArns'][0])
    else:
        # logger.error(f"Unable to find an assessment run in the last 7 days for {target_account.account_id}")
        return(None)

def get_findings(client, assessment_arn):
    findings = []
    list_response = client.list_findings(assessmentRunArns=[assessment_arn])
    while 'nextToken' in list_response:  # Gotta Catch 'em all!
        describe_response = client.describe_findings(findingArns=list_response['findingArns'])
        findings += describe_response['findings']
        list_response = client.list_findings(assessmentRunArns=[assessment_arn], nextToken=list_response['nextToken'])
    describe_response = client.describe_findings(findingArns=list_response['findingArns'])
    findings += describe_response['findings']
    return(findings)

def process_finding(finding, target_account, region, assessment_id):

    # Inspector is f---ing stupid in that there is no proper identified for a specific finding.
    # Ergo, to get a consistent object key, we will hash the id to get a finding_identified we can use across runs
    finding_id = hashlib.md5(finding['id'].encode()).hexdigest()

    resource_item = {}
    resource_item['awsAccountId']                   = target_account.account_id
    resource_item['awsAccountName']                 = target_account.account_name
    resource_item['resourceType']                   = RESOURCE_TYPE
    resource_item['awsRegion']                      = region
    resource_item['source']                         = "Antiope"
    resource_item['configurationItemCaptureTime']   = str(datetime.datetime.now())
    resource_item['configuration']                  = finding
    resource_item['supplementaryConfiguration']     = {}
    resource_item['resourceId']                     = f"{assessment_id}-{finding['assetAttributes']['agentId']}-{finding_id}"
    resource_item['ARN']                            = finding['arn']
    resource_item['resourceName']                   = f"{assessment_id}-{finding['assetAttributes']['agentId']}-{finding_id}"
    resource_item['resourceCreationTime']           = finding['createdAt']
    resource_item['errors']                         = {}


    save_resource_to_s3(RESOURCE_PATH, resource_item['resourceId'], resource_item)
