"""cfn-deletion-policy-retain-survives-stack-delete."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deletion-policy-retain-survives-stack-delete"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "sqs", "ssm"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeletionPolicy: Retain leaves the physical resource behind when the stack is deleted, while
    its default-policy twin is destroyed: the retained queue still accepts a message and the
    retained parameter still reads back, while SQS and SSM report the twins absent.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")

    retained_queue_name = _xname(ctx, "retained-q")
    default_queue_name = _xname(ctx, "default-q")
    retained_param = "/" + _xname(ctx, "retained-p")
    default_param = "/" + _xname(ctx, "default-p")
    value = _xname(ctx, "val")

    # The whole point of this check is that the stack delete will NOT remove these two, so they
    # need their own teardown. Registered before the deploy so LIFO runs them after the stack
    # cleanup, and written to tolerate the resource already being gone.
    ctx.on_cleanup(lambda: _delete_parameter_if_present(ssm, retained_param))
    ctx.on_cleanup(lambda: _delete_queue_by_name_if_present(sqs, retained_queue_name))

    result = _deploy_cfn(
        ctx,
        (DEPLOYMENTS / "deletion-policy-retain.yaml").read_text(),
        parameters={
            "RetainedQueueName": retained_queue_name,
            "DefaultQueueName": default_queue_name,
            "RetainedParameterName": retained_param,
            "DefaultParameterName": default_param,
            "ParameterValue": value,
        },
        timeout_s=600.0,
    )
    outputs = _outputs(result)
    stack_name = result["stack_name"]
    retained_url = outputs["RetainedQueueUrl"]
    default_url = outputs["DefaultQueueUrl"]

    # Baseline: all four exist and are indistinguishable apart from the policy.
    for url in (retained_url, default_url):
        assert (
            sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])[
                "Attributes"
            ]["VisibilityTimeout"]
            == "31"
        ), url
    for name in (retained_param, default_param):
        assert ssm.get_parameter(Name=name)["Parameter"]["Value"] == value, name

    # Delete the stack in-check; this is the behaviour under test, not teardown.
    _delete_stack_and_wait(ctx, stack_name, timeout_s=600.0)
    gone = ("ValidationError", f"Stack with id {stack_name} does not exist")
    _expect_client_error(
        lambda: cfn.describe_stacks(StackName=stack_name),
        {gone[0]},
        f"describe_stacks after delete of {stack_name}",
        gone[1],
    )

    # 1. The default-policy twins must be physically gone (eventual, so polled).
    _poll_for_client_error(
        lambda: sqs.get_queue_url(QueueName=default_queue_name),
        {"AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"},
        f"get_queue_url {default_queue_name} after stack delete",
        "The specified queue does not exist.",
        timeout_s=180.0,
    )
    _poll_for_client_error(
        lambda: ssm.get_parameter(Name=default_param),
        {"ParameterNotFound"},
        f"get_parameter {default_param} after stack delete",
        "",
        timeout_s=180.0,
    )

    # 2. The retained resources must still be fully usable, not merely listed.
    surviving_url = sqs.get_queue_url(QueueName=retained_queue_name)["QueueUrl"]
    sqs.send_message(QueueUrl=surviving_url, MessageBody="still-here")
    delivered = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=surviving_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        ).get("Messages", []),
        lambda msgs: bool(msgs),
        timeout_s=90.0,
        interval_s=2.0,
        description=f"message on retained queue {retained_queue_name}",
    )
    assert delivered[0]["Body"] == "still-here", delivered
    assert (
        sqs.get_queue_attributes(
            QueueUrl=surviving_url, AttributeNames=["VisibilityTimeout"]
        )["Attributes"]["VisibilityTimeout"]
        == "31"
    ), "the retained queue must keep the properties CloudFormation gave it"

    surviving_param = ssm.get_parameter(Name=retained_param)["Parameter"]
    assert surviving_param["Value"] == value, (
        f"retained SSM parameter holds {surviving_param['Value']!r} after the stack delete, "
        f"expected {value!r}"
    )


# ===== helpers =====
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


def _expect_client_error(fn, codes, description, message):
    """Require fn() to raise ClientError with an Error.Code in codes and exactly `message`;
    return the code."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        assert code in codes, (
            f"{description}: expected error code in {sorted(codes)}, got {code!r} ({exc})"
        )
        got = exc.response.get("Error", {}).get("Message")
        assert got == message, f"{description}: message {got!r} != {message!r}"
        return code
    raise AssertionError(f"{description}: call unexpectedly succeeded")


def _poll_for_client_error(fn, codes, description, message, *, timeout_s=120.0, interval_s=5.0):
    """Poll fn() until it raises ClientError with a code in codes (deletions are eventual), and
    require that error to carry exactly `message`."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in codes:
                got = exc.response.get("Error", {}).get("Message")
                assert got == message, f"{description}: message {got!r} != {message!r}"
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


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=600.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE; a failed delete raises."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as err:
            if "does not exist" in str(err):
                return "GONE"
            raise

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
