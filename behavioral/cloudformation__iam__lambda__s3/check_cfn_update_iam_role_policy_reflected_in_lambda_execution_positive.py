"""cfn-update-iam-role-policy-reflected-in-lambda-execution-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-update-iam-role-policy-reflected-in-lambda-execution-positive"
GROUP = "deployment-order"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack update that adds an inline S3 policy to a Lambda's execution role is applied such
    that the function's NEXT invocation actually gains the permission (and lacked it before)."""
    s3 = ctx.client("s3")
    bucket_name = _xname(ctx, "bkt")
    create_kwargs: dict[str, Any] = {"Bucket": bucket_name}
    # us-east-1 rejects an explicit LocationConstraint on CreateBucket
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": _xsvc_tags_kv()})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))

    function_name = _xname(ctx, "fn")

    def _template(with_s3_policy: bool) -> str:
        role_props: dict[str, Any] = {
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
        }
        if with_s3_policy:
            role_props["Policies"] = [
                {
                    "PolicyName": "s3access",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:ListBucket",
                                "Resource": f"arn:aws:s3:::{bucket_name}",
                            }
                        ],
                    },
                }
            ]
        return json.dumps(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Resources": {
                    "ExecRole": {"Type": "AWS::IAM::Role", "Properties": role_props},
                    "Function": {
                        "Type": "AWS::Lambda::Function",
                        "Properties": {
                            "FunctionName": function_name,
                            "Handler": "index.handler",
                            "Runtime": "python3.12",
                            "Timeout": 10,
                            "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                            "Code": {
                                "ZipFile": (
                                    "import boto3\n"
                                    "def handler(event, context):\n"
                                    "    s3 = boto3.client('s3')\n"
                                    "    try:\n"
                                    "        s3.head_bucket(Bucket=event['bucket'])\n"
                                    "        return {'allowed': True}\n"
                                    "    except Exception as exc:\n"
                                    "        resp = getattr(exc, 'response', None) or {}\n"
                                    "        code = resp.get('Error', {}).get('Code', type(exc).__name__)\n"
                                    "        return {'allowed': False, 'error': code}\n"
                                )
                            },
                        },
                    },
                },
            }
        )

    result = _deploy_cfn(ctx, _template(False), capabilities=["CAPABILITY_IAM"])
    _wait_lambda_active(ctx, function_name)

    _, before = _invoke_lambda(ctx, function_name, {"bucket": bucket_name})
    assert before["allowed"] is False, f"expected denied before the policy exists, got {before!r}"
    assert before["error"] in ("403", "AccessDenied"), (
        f"expected a 403/AccessDenied refusal before the policy exists, got {before['error']!r}"
    )

    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=result["stack_name"],
        TemplateBody=_template(True),
        Capabilities=["CAPABILITY_IAM"],
    )
    final_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=result["stack_name"])["Stacks"][0][
            "StackStatus"
        ],
        lambda s: s
        in {
            "UPDATE_COMPLETE",
            "UPDATE_FAILED",
            "UPDATE_ROLLBACK_COMPLETE",
            "UPDATE_ROLLBACK_FAILED",
        },
        timeout_s=180.0,
        interval_s=5.0,
        description="stack update terminal",
    )
    assert final_status == "UPDATE_COMPLETE", f"expected UPDATE_COMPLETE, got {final_status!r}"

    # IAM policy propagation is eventually consistent; poll the actual invocation outcome
    after = _poll_until(
        lambda: _invoke_lambda(ctx, function_name, {"bucket": bucket_name})[1],
        lambda body: body.get("allowed") is True,
        timeout_s=60.0,
        interval_s=3.0,
        description="lambda gains s3 permission after stack update",
    )
    assert after == {"allowed": True}, f"expected access granted after the policy update, got {after!r}"


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
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
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
    template_body = template.read_text() if isinstance(template, Path) else template
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


def _wait_lambda_active(ctx, function_name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
        lambda s: s == "Active",
        timeout_s=timeout_s,
        interval_s=3.0,
        description=f"lambda {function_name} Active",
    )


def _invoke_lambda(ctx, function_name: str, payload: dict | None = None):
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps(payload or {}).encode("utf-8"),
    )
    assert "FunctionError" not in resp, resp.get("FunctionError")
    body = json.loads(resp["Payload"].read())
    return resp, body


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
