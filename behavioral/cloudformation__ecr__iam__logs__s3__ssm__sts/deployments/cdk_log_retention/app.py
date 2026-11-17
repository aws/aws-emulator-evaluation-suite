import os

import aws_cdk as cdk
from aws_cdk import aws_logs as logs

_RETENTION = {
    "7": logs.RetentionDays.ONE_WEEK,
    "14": logs.RetentionDays.TWO_WEEKS,
}


class LogRetentionStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        logs.LogRetention(
            self, "Retention",
            log_group_name=os.environ["LOG_GROUP_NAME"],
            retention=_RETENTION[os.environ["RETENTION_DAYS"]],
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )


app = cdk.App()
LogRetentionStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                        region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
