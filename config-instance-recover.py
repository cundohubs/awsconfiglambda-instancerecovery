# Create EC2 instance alarms for resources in a region

import boto3
import argparse
import logging
import ConfigParser
import os
import json

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Create AWS clients
region = "us-east-1"
ec = boto3.client('ec2', region_name=region)
session = boto3.session.Session(region_name=region)

COMPLIANCE_STATES = {
    'COMPLIANT': 'COMPLIANT',
    'NON_COMPLIANT': 'NON_COMPLIANT',
    'NOT_APPLICABLE': 'NOT_APPLICABLE'
}

RECOVERABLE_INSTANCE_FAMILIES = ['t2', 'c4', 'm4']


def lambda_handler(event, context):
    global session
    function_arn = context.invoked_function_arn
    arn, provider, service, region_name, account_id, resource_type, resource_id = \
        function_arn.split(":")

    # logger.info("event: %s" % event)
    # logger.info("context: %s" % str(context))
    # Create Session with IAM User
    try:
        aws_access_key_id = context.aws_access_key_id
        aws_secret_access_key = context.aws_secret_access_key
        session = boto3.session.Session(aws_access_key_id=aws_access_key_id,
                                        aws_secret_access_key=aws_secret_access_key,
                                        region_name=region_name)
    except Exception:
        session = boto3.session.Session(region_name=region_name)

    invoking_event = json.loads(event['invokingEvent'])
    assert isinstance(invoking_event, dict)

    compliance_value = COMPLIANCE_STATES['NOT_APPLICABLE']
    if 'configurationItem' in invoking_event.keys():
        configuration_item = invoking_event['configurationItem']
        instance_id = configuration_item['resourceId']

        if is_new_instance(event, configuration_item) and \
                is_recoverable_instance(event, configuration_item):
            cw_creator = CloudWatchAlarmCreator(region_name, account_id)
            cw_creator.create_instance_recover_alarm(instance_id)
            cw_creator.create_instance_reboot_alarm(instance_id)
            compliance_value = COMPLIANCE_STATES['COMPLIANT']
        elif is_terminated_instance(event, configuration_item):
            cw_eliminator = CloudWatchAlarmsEliminator(region_name, account_id)
            cw_eliminator.delete_alarms_for_instance(instance_id)
            compliance_value = COMPLIANCE_STATES['NOT_APPLICABLE']

    config = session.client('config')
    response = config.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
                'ComplianceResourceId': invoking_event['configurationItem']['resourceId'],
                'ComplianceType': compliance_value,
                'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
            },
        ],
        ResultToken=event['resultToken'])


class CloudWatchAlarmCreator:
    def __init__(self, region, account_id):
        global session
        self.region = region
        self.account_id = account_id
        self.cw_client = session.client('cloudwatch')

    def create_instance_recover_alarm(self, instance_id):
        # Create Metric "Status Check Failed (System) for 5 Minutes"
        response = self.cw_client.put_metric_alarm(
            AlarmName="%s Instance Recover on Failed Status Check" % (instance_id),
            AlarmDescription='Status Check Failed (System) for 5 Minutes',
            ActionsEnabled=True,
            AlarmActions=[
                "arn:aws:automate:%s:ec2:recover" % self.region,
            ],
            MetricName='StatusCheckFailed_System',
            Namespace='AWS/EC2',
            Statistic='Average',
            Dimensions=[
                {
                    'Name': 'InstanceId',
                    'Value': instance_id
                },
            ],
            Period=60,
            EvaluationPeriods=5,
            Threshold=1.0,
            ComparisonOperator='GreaterThanOrEqualToThreshold'
        )
        return response

    def create_instance_reboot_alarm(self, instance_id):
        # Create Metric "Status Check Failed (Instance) for 20 Minutes"
        response = self.cw_client.put_metric_alarm(
            AlarmName="%s Instance Reboot on Failed Status Check" % (instance_id),
            AlarmDescription='Status Check Failed (Instance) for 20 Minutes',
            ActionsEnabled=True,
            AlarmActions=[
                "arn:aws:swf:%s:%s:action/actions/AWS_EC2.InstanceId.Reboot/1.0" % (self.region, self.account_id)
            ],
            MetricName='StatusCheckFailed_Instance',
            Namespace='AWS/EC2',
            Statistic='Average',
            Dimensions=[
                {
                    'Name': 'InstanceId',
                    'Value': instance_id
                },
            ],
            Period=60,
            EvaluationPeriods=20,
            Threshold=1.0,
            ComparisonOperator='GreaterThanOrEqualToThreshold'
        )
        return response


class CloudWatchAlarmsEliminator:
    def __init__(self, region, account_id):
        global session
        self.region = region
        self.account_id = account_id
        self.cw_client = session.client('cloudwatch')

    def delete_alarms_for_instance(self, instance_id):

        instance_reboot_alarm_alarms = self.cw_client.describe_alarms_for_metric(
            MetricName='StatusCheckFailed_Instance',
            Namespace='AWS/EC2',
            Dimensions=[{
                    'Name': 'InstanceId',
                    'Value': instance_id
                },])

        instance_recover_alarms = self.cw_client.describe_alarms_for_metric(
            MetricName='StatusCheckFailed_System',
            Namespace='AWS/EC2',
            Dimensions=[{
                    'Name': 'InstanceId',
                    'Value': instance_id
                },])
        instance_reboot_alarm_alarm_names = [alarm['AlarmName']
                for alarm in instance_reboot_alarm_alarms['MetricAlarms']]
        instance_recover_alarm_names = [alarm['AlarmName']
                for alarm in instance_recover_alarms['MetricAlarms']]
        alarm_names = instance_reboot_alarm_alarm_names + instance_recover_alarm_names

        response = self.cw_client.delete_alarms(
            AlarmNames=alarm_names
        )
        return response


def is_new_instance(event, configuration_item):
    resource_type = configuration_item['resourceType']

    status = configuration_item['configurationItemStatus']
    event_left_scope = event['eventLeftScope']
    return (status == 'OK' or status == 'ResourceDiscovered') and \
           not event_left_scope and \
           resource_type == "AWS::EC2::Instance"


def is_terminated_instance(event, configuration_item):
    try:
        event_left_scope = event['eventLeftScope']
        status = configuration_item['configurationItemStatus']
        return status == 'ResourceDeleted' and event_left_scope
    except Exception:
        return False


def is_recoverable_instance(event, configuration_item):
    try:
        configuration = configuration_item['configuration']
        instance_type = configuration['instanceType']
        family, size = instance_type.split('.')
        if family in RECOVERABLE_INSTANCE_FAMILIES:
            return True
    except Exception:
        return False
    return False


class Context:
    def __init__(self, **entries):
        self.__dict__.update(entries)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dryrun", help="Dry run - don't change anything in AWS")
    parser.add_argument("--account", help="AWS Account Name", default="QA")
    parser.add_argument("--secretkey", help="AWS Secret Key", default="deprecated")
    args = parser.parse_args()

    credentials = ConfigParser.ConfigParser()
    configs = ConfigParser.ConfigParser()

    home_dir = os.environ['HOME']
    credentials_file = home_dir + "/.aws/credentials"

    credentials.read(credentials_file)

    account_name = args.account
    aws_access_key_id = credentials.get(account_name, "aws_access_key_id")
    aws_secret_access_key = credentials.get(account_name, "aws_secret_access_key")

    # aws_access_key_id = args.accesskey
    # aws_secret_access_key = args.secretkey
    sample_arn = "arn:aws:lambda:us-east-1:123456789012:function:tagging-lambda"
    event = dict([("invokingEvent",
                   dict([("configurationItem",
                         dict([("configuration",
                               dict([("instanceId", "i-deaed543")])
                              ),
                               ("configurationItemStatus", "OK")])
                          )])),
                  ("eventLeftScope", False)
            ])
    context = dict([("invoked_function_arn", sample_arn),
                    ("keys", dict([
                    ("aws_access_key_id", aws_access_key_id),
                    ("aws_secret_access_key", aws_secret_access_key)]))])

    lambda_handler(str(event), Context(**context))
