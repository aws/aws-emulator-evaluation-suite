#!/usr/bin/env python3
"""CDK app with default version reporting: two stacks, the second reading the first's table name.

The cross-stack reference makes CDK export the name from the producer and import it in the consumer.

Context: producer_name, consumer_name, account, region, qualifier, param_name.
"""

import aws_cdk as cdk
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_ssm as ssm

app = cdk.App()
ctx = app.node.get_context
env = cdk.Environment(account=ctx("account"), region=ctx("region"))


def synthesizer():
    return cdk.DefaultStackSynthesizer(qualifier=ctx("qualifier"))


producer = cdk.Stack(app, ctx("producer_name"), synthesizer=synthesizer(), env=env)
table = ddb.Table(
    producer,
    "Table",
    partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
    billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
    removal_policy=cdk.RemovalPolicy.DESTROY,
)
consumer = cdk.Stack(app, ctx("consumer_name"), synthesizer=synthesizer(), env=env)
ssm.StringParameter(
    consumer, "TableNameParam", parameter_name=ctx("param_name"), string_value=table.table_name
)
app.synth()
