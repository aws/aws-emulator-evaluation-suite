"""cfn-lambda-role-trust-policy-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-role-trust-policy-positive"
GROUP = "iam-trust"
SERVICES = ["apigateway", "cloudformation", "lambda"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-created IAM role trusting lambda.amazonaws.com lets the deployed function
    actually assume its execution role and run — invoke it and assert the real output, and
    that CloudWatch Logs (which requires the assumed role's own permissions) received events."""
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
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
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
            },
            "EchoFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Handler": "index.handler",
                    "Runtime": "python3.12",
                    "Timeout": 30,
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Code": {
                        "ZipFile": {
                            "Fn::Join": [
                                "\n",
                                [
                                    "def handler(event, context):",
                                    "    return {'ok': True, 'received': event}",
                                ],
                            ]
                        }
                    },
                },
            },
        },
        "Outputs": {
            "FunctionArn": {"Value": {"Fn::GetAtt": ["EchoFunction", "Arn"]}},
            "FunctionName": {"Value": {"Ref": "EchoFunction"}},
        },
    }

    result = _deploy_cfn(ctx, json.dumps(template))
    lam = ctx.client("lambda")

    resp = lam.invoke(
        FunctionName=result["outputs"]["FunctionArn"],
        Payload=json.dumps({"ping": "pong"}).encode(),
    )
    assert resp["StatusCode"] == 200, f"expected StatusCode 200, got {resp['StatusCode']}"
    assert "FunctionError" not in resp, f"lambda invocation errored: {resp.get('FunctionError')!r}"
    payload = json.loads(resp["Payload"].read())
    assert payload["ok"] is True, f"expected payload['ok'] is True, got {payload!r}"
    assert payload["received"]["ping"] == "pong", (
        f"expected echoed 'ping': 'pong', got {payload.get('received')!r}"
    )

    # Deeper proof the assumed role actually worked end-to-end: the function's own execution
    # role granted it logs:CreateLogGroup/PutLogEvents, so a genuine invocation produces a real
    # CloudWatch log stream with events (a stub that fakes the Invoke response would not).
    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{result['outputs']['FunctionName']}"

    def _has_log_events():
        try:
            streams = logs.describe_log_streams(
                logGroupName=log_group, orderBy="LastEventTime", descending=True, limit=1
            )["logStreams"]
        except ClientError:
            return False
        return bool(streams) and streams[0].get("lastEventTimestamp") is not None

    _poll_until(
        _has_log_events,
        lambda ok: ok,
        timeout_s=60.0,
        interval_s=3.0,
        description="lambda log stream with events",
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
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
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template
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
            s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
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
