#!/usr/bin/env python3
"""CDK app with default version reporting under `LegacyStackSynthesizer`: no bootstrap needed.

The template is not an asset, so `cdk deploy` sends it inline as `TemplateBody`.

Context: stack_name, account, region, queue_name, param_name, param_value.
"""

import aws_cdk as cdk
from aws_cdk import aws_sqs as sqs
from aws_cdk import aws_ssm as ssm

app = cdk.App()
ctx = app.node.get_context
stack = cdk.Stack(
    app,
    ctx("stack_name"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(account=ctx("account"), region=ctx("region")),
)
queue = sqs.Queue(stack, "Queue", queue_name=ctx("queue_name"))
ssm.StringParameter(
    stack, "Param", parameter_name=ctx("param_name"), string_value=ctx("param_value")
)
cdk.CfnOutput(stack, "QueueUrl", value=queue.queue_url)
app.synth()
