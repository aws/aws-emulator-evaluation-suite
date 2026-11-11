"""cfn-deploy-eventbridge-rule-cloudfront-invalidation-lambda."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-eventbridge-rule-cloudfront-invalidation-lambda"
GROUP = "deployment-order"
SERVICES = ["cloudfront", "events"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN stack deploys an events-trusted IAM role, a Lambda target and an EventBridge rule;
    the deployed rule successfully triggers the Lambda, which calls CreateInvalidation on a
    real CloudFront distribution."""
    cf = ctx.client("cloudfront")
    events = ctx.client("events")

    dist = _create_test_distribution(ctx)

    stack = _deploy_cfn(
        ctx,
        json.dumps(_template()),
        parameters={"DistributionId": dist["id"], "DistributionArn": dist["arn"]},
    )
    assert "FunctionName" in stack["outputs"], (
        f"expected a FunctionName output from the deployed stack, got outputs={stack['outputs']!r}"
    )

    marker = _xname(ctx, "trg")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.cloudfront-automation",
                "DetailType": "TriggerInvalidation",
                "Detail": json.dumps({"marker": marker}),
            }
        ]
    )

    def _list_invalidations():
        return cf.list_invalidations(DistributionId=dist["id"]).get(
            "InvalidationList", {}
        ).get("Items", [])

    items = _poll_until(
        _list_invalidations,
        lambda items: len(items) >= 1,
        timeout_s=90,
        interval_s=5,
        description="CloudFront invalidation created by the EventBridge-triggered Lambda",
    )
    # EventBridge delivers to Lambda at least once, so a redelivery may add an invalidation;
    # every invalidation on the distribution must be the Lambda's own.
    assert len(items) >= 1, (
        f"expected at least one CloudFront invalidation on distribution {dist['id']!r} created by "
        f"the EventBridge-triggered Lambda, got InvalidationList.Items={items!r}"
    )
    for item in items:
        batch = cf.get_invalidation(DistributionId=dist["id"], Id=item["Id"])["Invalidation"][
            "InvalidationBatch"
        ]
        assert batch["Paths"] == {"Quantity": 1, "Items": ["/*"]}, (
            f"expected the Lambda's invalidation to carry exactly the path '/*', got {batch['Paths']!r}"
        )


def _template() -> dict[str, Any]:
    lambda_code = (
        "import json, os, time\n"
        "import boto3\n\n"
        "def handler(event, context):\n"
        "    cf = boto3.client('cloudfront')\n"
        "    resp = cf.create_invalidation(\n"
        "        DistributionId=os.environ['DISTRIBUTION_ID'],\n"
        "        InvalidationBatch={\n"
        "            'Paths': {'Quantity': 1, 'Items': ['/*']},\n"
        "            'CallerReference': str(time.time()) + '-' + context.aws_request_id,\n"
        "        },\n"
        "    )\n"
        "    return {'invalidationId': resp['Invalidation']['Id']}\n"
    )
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "DistributionId": {"Type": "String"},
            "DistributionArn": {"Type": "String"},
        },
        "Resources": {
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            # No logs grant: the function never creates a log group that
                            # outlives the stack.
                            "PolicyName": "invalidate",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "cloudfront:CreateInvalidation",
                                        "Resource": {"Ref": "DistributionArn"},
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "InvalidatorFn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Timeout": 30,
                    "Environment": {
                        "Variables": {"DISTRIBUTION_ID": {"Ref": "DistributionId"}}
                    },
                    "Code": {"ZipFile": lambda_code},
                },
            },
            "TriggerRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "EventPattern": {
                        "source": ["sim2real.cloudfront-automation"],
                        "detail-type": ["TriggerInvalidation"],
                    },
                    "Targets": [
                        {
                            "Id": "invalidator",
                            "Arn": {"Fn::GetAtt": ["InvalidatorFn", "Arn"]},
                        }
                    ],
                },
            },
            "EventsInvokePermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction",
                    "FunctionName": {"Ref": "InvalidatorFn"},
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["TriggerRule", "Arn"]},
                },
            },
        },
        "Outputs": {
            "FunctionName": {"Value": {"Ref": "InvalidatorFn"}},
            "RuleName": {"Value": {"Ref": "TriggerRule"}},
        },
    }


def _create_test_distribution(ctx) -> dict[str, str]:
    cf = ctx.client("cloudfront")
    caller_ref = _xname(ctx, "dist")
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": {
                "CallerReference": caller_ref,
                "Comment": caller_ref,
                "Enabled": True,
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": "origin1",
                            "DomainName": "example.com",
                            "CustomOriginConfig": {
                                "HTTPPort": 80,
                                "HTTPSPort": 443,
                                "OriginProtocolPolicy": "https-only",
                            },
                        }
                    ],
                },
                "DefaultCacheBehavior": {
                    "TargetOriginId": "origin1",
                    "ViewerProtocolPolicy": "redirect-to-https",
                    "ForwardedValues": {
                        "QueryString": False,
                        "Cookies": {"Forward": "none"},
                    },
                    "MinTTL": 0,
                    "TrustedSigners": {"Enabled": False, "Quantity": 0},
                },
            },
            "Tags": {
                "Items": [
                    {"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()
                ]
            },
        }
    )
    dist_id = resp["Distribution"]["Id"]
    dist_arn = resp["Distribution"]["ARN"]
    ctx.on_cleanup(lambda: _delete_test_distribution(ctx, dist_id))
    return {"id": dist_id, "arn": dist_arn}


def _delete_test_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")

    def _status():
        return cf.get_distribution(Id=dist_id)["Distribution"]["Status"]

    # a distribution must finish its first deployment before it accepts another config update
    _poll_until(
        _status,
        lambda s: s == "Deployed",
        timeout_s=1200,
        interval_s=15,
        description=f"distribution {dist_id} initial deployment",
    )

    cfg = cf.get_distribution_config(Id=dist_id)
    etag = cfg["ETag"]
    dc = cfg["DistributionConfig"]
    if dc.get("Enabled"):
        dc["Enabled"] = False
        cf.update_distribution(Id=dist_id, DistributionConfig=dc, IfMatch=etag)

    _poll_until(
        _status,
        lambda s: s == "Deployed",
        timeout_s=1200,
        interval_s=15,
        description=f"distribution {dist_id} disabled and redeployed",
    )
    etag = cf.get_distribution_config(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if hasattr(template, "read_text") else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
