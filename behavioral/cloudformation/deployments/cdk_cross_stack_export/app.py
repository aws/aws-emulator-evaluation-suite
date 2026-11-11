#!/usr/bin/env python3
"""Asset-free CDK app: two stacks joined by CDK's automatic cross-stack reference.

Producer owns an SSM String Parameter; Consumer's own parameter is initialized from
`producer.param.string_value`, which CDK wires as an Output+Export on Producer and an
Fn::ImportValue on Consumer, and makes Consumer depend on Producer.

Context:
  account, region          -- the environment
  stack_prefix              -- stack id prefix; stacks are "<prefix>-producer"/"<prefix>-consumer"
  producer_param_name       -- physical Name of Producer's parameter
  consumer_param_name       -- physical Name of Consumer's parameter
  producer_value            -- Value of Producer's parameter (the exported value)
  producer_description      -- Description of Producer's parameter (not exported; a bystander)
"""
import aws_cdk as cdk
from aws_cdk import aws_ssm as ssm


class ProducerStack(cdk.Stack):
    def __init__(self, scope, construct_id, *, param_name, value, description, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        self.param = ssm.StringParameter(
            self, "Exported",
            parameter_name=param_name,
            string_value=value,
            description=description,
        )


class ConsumerStack(cdk.Stack):
    def __init__(self, scope, construct_id, *, param_name, producer_param, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        ssm.StringParameter(
            self, "Imported",
            parameter_name=param_name,
            string_value=producer_param.string_value,
        )


app = cdk.App()
prefix = app.node.try_get_context("stack_prefix")
env = cdk.Environment(
    account=app.node.try_get_context("account"),
    region=app.node.try_get_context("region"),
)

producer = ProducerStack(
    app, f"{prefix}-producer",
    param_name=app.node.try_get_context("producer_param_name"),
    value=app.node.try_get_context("producer_value"),
    description=app.node.try_get_context("producer_description"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=env,
)
ConsumerStack(
    app, f"{prefix}-consumer",
    param_name=app.node.try_get_context("consumer_param_name"),
    producer_param=producer.param,
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=env,
)

app.synth()
