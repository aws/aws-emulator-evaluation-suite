"""cfn-deploy-broken-lambda-role-negative."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-broken-lambda-role-negative"

GROUP = "overly-permissive"

SERVICES = ["cloudformation", "lambda", "s3", "sqs"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CFN stack deploys Lambda+SQS but role lacks sqs:SendMessage; invoke must show AccessDenied."""
    template = (DEPLOYMENTS / "lambda-sqs-broken-perms.yaml").read_text()
    result = _deploy_cfn(ctx, template)
    fn_name = result["outputs"]["FunctionName"]
    queue_url = result["outputs"]["QueueUrl"]

    invoke_result = _invoke_lambda(ctx, fn_name, {"data": "should-fail"})
    payload = invoke_result["payload"]
    payload_str = json.dumps(payload) if isinstance(payload, dict) else str(payload)
    assert (
        "AccessDenied" in payload_str
        or "AccessDeniedException" in payload_str
        or invoke_result.get("status_code") == 403
    ), f"Expected AccessDenied in response, got: {payload_str}"

    sqs = ctx.client("sqs")
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2
    )
    msgs = resp.get("Messages", [])
    assert not msgs, (
        "Queue should be empty when Lambda lacks sqs:SendMessage permission"
    )

    # Restore leg: grant the missing permission on the same role and prove the identical call now
    # succeeds — without this, "denied" is indistinguishable from "this Lambda-to-SQS wiring never
    # delivers anything".
    role_name = ctx.client("lambda").get_function_configuration(FunctionName=fn_name)[
        "Role"
    ].split("/")[-1]
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    iam = ctx.client("iam")
    fix_policy_name = "sim2real-xsvc-allow-send"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=fix_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sqs:SendMessage",
                        "Resource": queue_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=fix_policy_name)
    )

    def _try_restored_invoke() -> dict[str, Any]:
        return _invoke_lambda(ctx, fn_name, {"data": "should-succeed"})

    _poll_until(
        _try_restored_invoke,
        lambda r: isinstance(r.get("payload"), dict)
        and r["payload"].get("statusCode") == 200,
        timeout_s=30.0,
        interval_s=3.0,
        description=(
            "Lambda invoke succeeds after granting sqs:SendMessage "
            "(bounded retry over IAM policy propagation)"
        ),
    )
    resp2 = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
    )
    assert resp2.get("Messages"), (
        "Expected the restored call's message to arrive in the queue"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


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


def _invoke_lambda(ctx, name: str, payload: dict | None = None) -> dict[str, Any]:
    """Invoke a Lambda synchronously; return {status_code[, error], payload|payload_raw}."""
    resp = ctx.client("lambda").invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload or {}).encode(),
    )
    body = resp["Payload"].read()
    result: dict[str, Any] = {"status_code": resp["StatusCode"]}
    if resp.get("FunctionError"):
        result["error"] = resp["FunctionError"]
    try:
        result["payload"] = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        result["payload_raw"] = body.decode("utf-8", errors="replace")
    return result


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
