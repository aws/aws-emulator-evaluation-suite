"""cfn-declared-log-group-receives-lambda-logs."""

from __future__ import annotations

import json
import time
import urllib.parse
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-declared-log-group-receives-lambda-logs"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "iam", "lambda", "logs"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-declared log group with 1-day retention is the one the deployed Lambda logs
    into: its role grants logs:PutLogEvents on that group's ARN without logs:CreateLogGroup, and the
    invocation's marker appears in the group's events."""
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    awslambda = ctx.client("lambda")

    function_name = _xname(ctx, "logemit")
    log_group_name = f"/aws/lambda/{function_name}"
    ctx.on_cleanup(lambda: _delete_log_group_if_present(logs, log_group_name))

    result = _deploy_cfn(
        ctx,
        (DEPLOYMENTS / "declared-log-group.yaml").read_text(),
        parameters={"FunctionName": function_name},
        capabilities=["CAPABILITY_IAM"],
        timeout_s=900.0,
    )
    outputs = _outputs(result)
    assert outputs["LogGroupName"] == log_group_name, (
        f"Ref of the log group is {outputs['LogGroupName']!r}; !Sub must derive "
        f"{log_group_name!r} from the function name"
    )

    # 1. The group exists with the declared retention, and GetAtt Arn matches what Logs reports.
    described = _poll_until(
        lambda: [
            g
            for g in logs.describe_log_groups(logGroupNamePrefix=log_group_name)[
                "logGroups"
            ]
            if g["logGroupName"] == log_group_name
        ],
        lambda groups: bool(groups),
        timeout_s=120.0,
        interval_s=5.0,
        description=f"log group {log_group_name} present",
    )[0]
    assert described.get("retentionInDays") == 1, (
        f"log group retention is {described.get('retentionInDays')!r}, expected 1; a group "
        "created implicitly on first write has no retention at all"
    )
    # GetAtt Arn ends in ':*' while DescribeLogGroups may or may not; compare the group ARN.
    assert _strip_wildcard(outputs["LogGroupArn"]) == _strip_wildcard(described["arn"]), (
        f"GetAtt Arn {outputs['LogGroupArn']!r} disagrees with the Logs-reported ARN "
        f"{described['arn']!r}"
    )

    # 2. The role really is scoped to that group and really cannot create groups.
    policy = iam.get_role_policy(
        RoleName=outputs["ExecutionRoleName"], PolicyName="declared-log-group-only"
    )
    document = _policy_document(policy["PolicyDocument"])
    statements = document["Statement"]
    if isinstance(statements, dict):
        statements = [statements]
    resources = json.dumps([s.get("Resource") for s in statements])
    assert log_group_name in resources, (
        f"the inline policy is not scoped to the declared group: {resources}"
    )
    actions = json.dumps([s.get("Action") for s in statements])
    assert "logs:PutLogEvents" in actions, actions
    assert "logs:CreateLogGroup" not in actions, (
        "the fixture must NOT grant logs:CreateLogGroup -- log events prove the "
        f"CloudFormation-declared group was used: {actions}"
    )

    # 3. The function logs land in that exact group.
    marker = _xname(ctx, "marker")
    payload = _invoke_json(awslambda, outputs["EmitterFunctionName"], {"marker": marker})
    assert payload["marker"] == marker, payload

    events = _poll_until(
        lambda: logs.filter_log_events(
            logGroupName=log_group_name, filterPattern="SIM2REAL_MARKER"
        ).get("events", []),
        lambda evts: any(marker in e.get("message", "") for e in evts),
        timeout_s=180.0,
        interval_s=5.0,
        description=f"marker {marker} in {log_group_name}",
    )
    matched = [e for e in events if marker in e.get("message", "")]
    assert matched, events
    assert matched[0]["logStreamName"], matched[0]

    streams = logs.describe_log_streams(logGroupName=log_group_name)["logStreams"]
    assert streams, (
        f"{log_group_name} has no log streams even though filter_log_events matched"
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


def _outputs(result: dict) -> dict:
    """Deployment results may nest outputs under 'outputs' or expose them flat."""
    return result.get("outputs", result)


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


def _invoke_json(awslambda, function_name: str, payload: dict) -> dict:
    """Synchronously invoke a Lambda and decode its JSON result (asserting no function error)."""
    response = awslambda.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode(),
    )
    body = response["Payload"].read().decode()
    assert not response.get("FunctionError"), f"{function_name} failed: {body}"
    return json.loads(body)


def _strip_wildcard(arn: str) -> str:
    """Log group ARNs are reported with and without the trailing ':*' depending on the API."""
    return arn[:-2] if arn.endswith(":*") else arn


def _policy_document(document) -> dict:
    """IAM policy documents come back as a dict or as a URL-encoded JSON string."""
    if isinstance(document, dict):
        return document
    return json.loads(urllib.parse.unquote(document))


def _delete_log_group_if_present(logs, log_group_name: str) -> None:
    """Best-effort log group teardown; already-deleted is not an error."""
    try:
        logs.delete_log_group(logGroupName=log_group_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=600.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup).

    Waits up to timeout_s for DELETE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=timeout_s,
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
    timeout_s=600.0,
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
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
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
