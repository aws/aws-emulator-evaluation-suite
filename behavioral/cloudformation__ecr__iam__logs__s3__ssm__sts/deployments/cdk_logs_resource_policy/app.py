import json
import os

import aws_cdk as cdk
from aws_cdk import aws_logs as logs
from aws_cdk import custom_resources as cr


class LogsResourcePolicyStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        log_group = logs.LogGroup(
            self,
            "Target",
            log_group_name=os.environ["LOG_GROUP_NAME"],
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        policy_name = os.environ["POLICY_NAME"]
        actions = json.loads(os.environ["POLICY_ACTIONS"])
        document = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "Sim2realAllowEventsWrite",
                        "Effect": "Allow",
                        "Principal": {"Service": "events.amazonaws.com"},
                        "Action": actions,
                        "Resource": log_group.log_group_arn,
                        "Condition": {
                            "StringEquals": {
                                "aws:SourceAccount": os.environ["CDK_DEFAULT_ACCOUNT"]
                            },
                        },
                    }
                ],
            }
        )
        resource = cr.AwsCustomResource(
            self,
            "ResourcePolicy",
            resource_type="Custom::CloudWatchLogsResourcePolicy",
            on_create=cr.AwsSdkCall(
                service="CloudWatchLogs",
                action="putResourcePolicy",
                parameters={"policyName": policy_name, "policyDocument": document},
                physical_resource_id=cr.PhysicalResourceId.of(policy_name),
            ),
            on_update=cr.AwsSdkCall(
                service="CloudWatchLogs",
                action="putResourcePolicy",
                parameters={"policyName": policy_name, "policyDocument": document},
                physical_resource_id=cr.PhysicalResourceId.of(policy_name),
            ),
            on_delete=cr.AwsSdkCall(
                service="CloudWatchLogs",
                action="deleteResourcePolicy",
                parameters={"policyName": policy_name},
                ignore_error_codes_matching="ResourceNotFoundException",
            ),
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE,
            ),
        )
        resource.node.add_dependency(log_group)


app = cdk.App()
LogsResourcePolicyStack(
    app,
    os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(
        account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"]
    ),
)
app.synth()
