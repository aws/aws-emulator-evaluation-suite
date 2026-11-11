"""CDK app for the asset-lifecycle checks: one Lambda whose code asset changes between v1 and v2.

Context:
  account, region  -- deploy environment
  qualifier        -- bootstrap qualifier for the DefaultStackSynthesizer
  stack_name       -- the stack id
  code_dir         -- "lambda_v1" or "lambda_v2" (default "lambda_v1"), selects the asset content
"""
import aws_cdk as cdk
from aws_cdk import aws_lambda as _lambda


class AssetLifecycleStack(cdk.Stack):
    def __init__(self, scope, construct_id, code_dir, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        fn = _lambda.Function(
            self, "Fn",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset(code_dir),
        )
        cdk.CfnOutput(self, "FunctionName", value=fn.function_name)


app = cdk.App()
qualifier = app.node.try_get_context("qualifier")
if not qualifier:
    raise ValueError("this app requires a `qualifier` context value")

AssetLifecycleStack(
    app,
    app.node.try_get_context("stack_name") or "AssetLifecycleStack",
    code_dir=app.node.try_get_context("code_dir") or "lambda_v1",
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=qualifier),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
