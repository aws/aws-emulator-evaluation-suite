"""cdk-secret-param - a generated SecretsManager Secret and a tagged plain SSM StringParameter."""
import os

import aws_cdk as cdk
from aws_cdk import aws_secretsmanager as secretsmanager
from aws_cdk import aws_ssm as ssm


class SecretParamStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        secret = secretsmanager.Secret(
            self, "Secret",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                password_length=40, exclude_punctuation=True,
            ),
        )
        param = ssm.StringParameter(
            self, "Param",
            string_value="sim2real-cdk-secret-param-placeholder",
        )
        cdk.Tags.of(param).add("sim2real-role", "tagged-parameter")
        cdk.Tags.of(self).add("sim2real", os.environ["CHECK_ID"])
        cdk.CfnOutput(self, "SecretArn", value=secret.secret_arn)
        cdk.CfnOutput(self, "ParamName", value=param.parameter_name)


app = cdk.App()
SecretParamStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(
        account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"],
    ),
)
app.synth()
