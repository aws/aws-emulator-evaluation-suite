"""cfn-update-rollback-restores-last-good-value-negative."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-update-rollback-restores-last-good-value-negative"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "sqs", "ssm"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack update whose later resource fails rolls back to UPDATE_ROLLBACK_COMPLETE, restoring
    the already-changed SSM parameter and the stack's recorded parameters to the last good value,
    and leaves no failed queue behind; a following valid update still applies."""
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    sqs = ctx.client("sqs")

    param_name = "/" + _xname(ctx, "rollback-p")
    good_value = _xname(ctx, "good")
    bad_value = _xname(ctx, "bad")
    # Deliberately missing the .fifo suffix that FifoQueue: true requires.
    failing_queue_name = _xname(ctx, "doomed-q")

    ctx.on_cleanup(lambda: _delete_parameter_if_present(ssm, param_name))
    ctx.on_cleanup(lambda: _delete_queue_by_name_if_present(sqs, failing_queue_name))

    template = (DEPLOYMENTS / "update-rollback-parameter.yaml").read_text()
    base_parameters = {
        "ParameterName": param_name,
        "FailingQueueName": failing_queue_name,
    }
    result = _deploy_cfn(
        ctx,
        template,
        parameters={
            **base_parameters,
            "ParameterValue": good_value,
            "IncludeFailure": "false",
        },
        timeout_s=600.0,
    )
    stack_name = result["stack_name"]
    initial = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert initial == good_value, (
        f"setup deploy wrote {initial!r} to {param_name}, expected the good value {good_value!r}"
    )

    # ---- the update that must fail ----
    status = _update_stack_and_wait(
        ctx,
        stack_name,
        template,
        parameters={
            **base_parameters,
            "ParameterValue": bad_value,
            "IncludeFailure": "true",
        },
        timeout_s=900.0,
    )
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"stack ended in {status}; a resource CREATE_FAILED during an update must drive the "
        "stack to UPDATE_ROLLBACK_COMPLETE"
    )

    # 1. The failure was the one we engineered, and CloudFormation reported it -- not some
    #    unrelated failure (a permission error, a quota) that would happen to end in the same
    #    terminal status.
    events = _stack_resource_events(cfn, stack_name)
    doomed = [e for e in events if e.get("LogicalResourceId") == "Doomed"]
    failures = [e for e in doomed if e["ResourceStatus"] == "CREATE_FAILED"]
    assert failures, (
        f"no CREATE_FAILED event for the invalid FIFO queue: {[e['ResourceStatus'] for e in doomed]}"
    )
    reason = failures[0].get("ResourceStatusReason", "")
    assert "fifo" in reason.lower(), (
        f"CREATE_FAILED reason does not name the engineered FIFO-suffix defect: {reason!r}"
    )

    # 2. The last-good value must be back -- read from SSM, not from the stack's metadata.
    restored = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert restored == good_value, (
        f"after UPDATE_ROLLBACK_COMPLETE the parameter holds {restored!r}; rollback must restore "
        f"the last good value {good_value!r} (it was changed to {bad_value!r} during the update)"
    )

    # 3. The resource that could not be created must not exist in any form.
    _poll_for_client_error(
        lambda: sqs.get_queue_url(QueueName=failing_queue_name),
        {"AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"},
        f"get_queue_url {failing_queue_name} after update rollback",
        timeout_s=120.0,
    )

    # 4. The stack's own record of its parameters must have been reverted as well, otherwise the
    #    next update would diff against the failed values.
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    recorded = {p["ParameterKey"]: p.get("ParameterValue") for p in stack["Parameters"]}
    assert recorded["ParameterValue"] == good_value, (
        f"DescribeStacks still reports the failed parameter value: {recorded}"
    )
    assert recorded["IncludeFailure"] == "false", recorded
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    assert outputs["TrackedParameterValue"] == good_value, outputs

    # 5. Control: the stack is not wedged. An update that CAN succeed still works afterwards.
    next_value = _xname(ctx, "next")
    status = _update_stack_and_wait(
        ctx,
        stack_name,
        template,
        parameters={
            **base_parameters,
            "ParameterValue": next_value,
            "IncludeFailure": "false",
        },
        timeout_s=900.0,
    )
    assert status == "UPDATE_COMPLETE", status
    final = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert final == next_value, (
        f"post-rollback update wrote {final!r} to {param_name}, expected {next_value!r}; "
        "the stack must not still be wedged on the earlier rollback"
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


def _poll_for_client_error(fn, codes, description, *, timeout_s=120.0, interval_s=5.0):
    """Poll fn() until it raises ClientError with a code in codes (deletions are eventual)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in codes:
                return code
            raise AssertionError(
                f"{description}: expected error code in {sorted(codes)}, got {code!r} ({exc})"
            )
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: still succeeding after {timeout_s}s; expected one of "
                f"{sorted(codes)}"
            )
        time.sleep(interval_s)


def _stack_resource_events(cfn, stack_name: str) -> list[dict[str, Any]]:
    """Every resource event for a stack, oldest first."""
    events: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack_name}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_events(**kwargs)
        events.extend(page.get("StackEvents", []))
        token = page.get("NextToken")
        if not token:
            break
    return list(reversed(events))


def _delete_parameter_if_present(ssm, name: str) -> None:
    """SSM parameter teardown; a parameter already gone is not an error."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise


def _delete_queue_by_name_if_present(sqs, queue_name: str) -> None:
    """Queue teardown by name; a queue already gone is not an error."""
    try:
        url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in {
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        }:
            return
        raise
    sqs.delete_queue(QueueUrl=url)


def _update_stack_and_wait(
    ctx,
    stack_name: str,
    template,
    *,
    parameters=None,
    capabilities=None,
    timeout_s=600.0,
) -> str:
    """Update a stack and poll to a terminal status, which is RETURNED rather than asserted:
    failed updates are the behaviour under test, so the caller decides which status is correct."""
    cfn = ctx.client("cloudformation")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": stack_name,
        "TemplateBody": template_body,
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    cfn.update_stack(**kwargs)
    return _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {
            "UPDATE_COMPLETE",
            "UPDATE_FAILED",
            "UPDATE_ROLLBACK_COMPLETE",
            "UPDATE_ROLLBACK_FAILED",
        },
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"update of stack {stack_name}",
    )


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=600.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown: a stack that does not go raises)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

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
