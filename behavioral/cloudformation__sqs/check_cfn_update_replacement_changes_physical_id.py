"""cfn-update-replacement-changes-physical-id."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-update-replacement-changes-physical-id"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "sqs"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Changing a create-only property must REPLACE the resource: a new physical id behind the
    same logical id, the new resource working, and the old one kept only where
    UpdateReplacePolicy: Retain says so."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    prefix_v1 = _xname(ctx, "rep1")
    prefix_v2 = _xname(ctx, "rep2")
    # Registered before the deploy so LIFO runs them after the stack cleanup. The v1 retained
    # queue is deliberately orphaned by the update, so nothing else will ever remove it.
    for prefix in (prefix_v1, prefix_v2):
        ctx.on_cleanup(
            lambda p=prefix: _delete_queue_by_name_if_present(sqs, f"{p}-retain")
        )

    template = (DEPLOYMENTS / "update-replace-policy.yaml").read_text()
    result = _deploy_cfn(
        ctx, template, parameters={"NamePrefix": prefix_v1}, timeout_s=600.0
    )
    stack_name = result["stack_name"]
    outputs = _outputs(result)

    old_retained_url = outputs["RetainedOnReplaceUrl"]
    old_plain_url = outputs["ReplacedNormallyUrl"]
    assert outputs["RetainedOnReplaceName"] == f"{prefix_v1}-retain", outputs
    old_physical = {
        logical: _physical_id(cfn, stack_name, logical)
        for logical in ("RetainedOnReplace", "ReplacedNormally")
    }
    assert old_physical["RetainedOnReplace"] == old_retained_url, (
        f"PhysicalResourceId {old_physical['RetainedOnReplace']!r} does not match Ref "
        f"{old_retained_url!r}; for AWS::SQS::Queue both are the queue URL"
    )
    sqs.send_message(QueueUrl=old_retained_url, MessageBody="pre-replacement")

    # ---- the update that forces replacement of both queues ----
    status = _update_stack_and_wait(
        ctx, stack_name, template, parameters={"NamePrefix": prefix_v2}, timeout_s=900.0
    )
    assert status == "UPDATE_COMPLETE", (
        f"stack ended in {status}; renaming a queue is a valid replacing update"
    )

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    new_outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}

    # 1. Same logical ids, different physical ids: that is what replacement means.
    for logical in ("RetainedOnReplace", "ReplacedNormally"):
        new_id = _physical_id(cfn, stack_name, logical)
        assert new_id != old_physical[logical], (
            f"{logical} kept physical id {new_id!r} across a create-only property change; "
            "CloudFormation must replace the resource, not mutate it in place"
        )
    assert new_outputs["RetainedOnReplaceName"] == f"{prefix_v2}-retain", new_outputs
    assert new_outputs["ReplacedNormallyName"] == f"{prefix_v2}-plain", new_outputs

    # 2. The replacements are real, working queues under the new names.
    for url, name in (
        (new_outputs["RetainedOnReplaceUrl"], f"{prefix_v2}-retain"),
        (new_outputs["ReplacedNormallyUrl"], f"{prefix_v2}-plain"),
    ):
        assert sqs.get_queue_url(QueueName=name)["QueueUrl"] == url, name
        sqs.send_message(QueueUrl=url, MessageBody="post-replacement")
        messages = _poll_until(
            lambda u=url: sqs.receive_message(
                QueueUrl=u, MaxNumberOfMessages=1, WaitTimeSeconds=5
            ).get("Messages", []),
            lambda msgs: bool(msgs),
            timeout_s=90.0,
            interval_s=2.0,
            description=f"message on replacement queue {name}",
        )
        assert messages[0]["Body"] == "post-replacement", messages
        assert (
            sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])[
                "Attributes"
            ]["VisibilityTimeout"]
            == "43"
        ), name

    # 3. UpdateReplacePolicy: Retain kept the predecessor, message and all.
    surviving_url = sqs.get_queue_url(QueueName=f"{prefix_v1}-retain")["QueueUrl"]
    assert surviving_url == old_retained_url, (
        f"the retained predecessor is at {surviving_url!r}, expected the original "
        f"{old_retained_url!r}"
    )
    kept = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=surviving_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        ).get("Messages", []),
        lambda msgs: bool(msgs),
        timeout_s=90.0,
        interval_s=2.0,
        description=f"pre-replacement message still on {prefix_v1}-retain",
    )
    assert kept[0]["Body"] == "pre-replacement", (
        f"the retained queue lost its contents: {kept}"
    )

    # 4. Without UpdateReplacePolicy the predecessor must be deleted.
    _poll_for_client_error(
        lambda: sqs.get_queue_url(QueueName=f"{prefix_v1}-plain"),
        {"AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"},
        f"get_queue_url {prefix_v1}-plain after replacement",
        timeout_s=180.0,
    )
    assert old_plain_url != new_outputs["ReplacedNormallyUrl"], (
        f"the replacement queue reused the deleted predecessor's URL "
        f"{old_plain_url!r}; CloudFormation must not recycle a queue URL"
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


def _physical_id(cfn, stack_name: str, logical_id: str) -> str:
    """The PhysicalResourceId CloudFormation currently records for a logical id."""
    return cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId=logical_id
    )["StackResourceDetail"]["PhysicalResourceId"]


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
    """Update a stack and poll to a terminal status, which is RETURNED rather than asserted: the
    caller decides which terminal status is correct."""
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
