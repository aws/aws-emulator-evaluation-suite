"""hook-result-lifecycle."""

from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hook-result-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """With no Hook registered, ListHookResults on a real change set target succeeds with no results,
    and GetHookResult for an unknown HookResultId is HookResultNotFound ("The hook result was not
    found."), the rest state before any RecordHandlerProgress transition."""
    cfn = ctx.client("cloudformation")

    stack_name = ctx.unique_name("sim2real-hookresult-")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"Topic": {"Type": "AWS::SNS::Topic"}},
        }
    )
    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))
    _wait_stack_status(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=180)

    updated_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Topic": {"Type": "AWS::SNS::Topic"},
                "Queue": {"Type": "AWS::SQS::Queue"},
            },
        }
    )
    cs_name = ctx.unique_name("sim2real-hookcs-")
    cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        ChangeSetType="UPDATE",
        TemplateBody=updated_template,
    )
    ctx.on_cleanup(lambda: _safe_delete_change_set(cfn, stack_name, cs_name))
    described = _poll_until(
        lambda: cfn.describe_change_set(StackName=stack_name, ChangeSetName=cs_name),
        lambda r: r["Status"] in ("CREATE_COMPLETE", "FAILED"),
        timeout_s=120,
        interval_s=5,
    )
    assert described["Status"] == "CREATE_COMPLETE", described.get("StatusReason")
    change_set_arn = described["ChangeSetId"]

    # ListHookResults addresses a target, so a target with no Hook invocations is an empty
    # collection rather than an error.
    list_resp = cfn.list_hook_results(TargetType="CHANGE_SET", TargetId=change_set_arn)
    assert list_resp.get("TargetType") == "CHANGE_SET", list_resp
    assert list_resp.get("TargetId") == change_set_arn, list_resp
    assert list_resp.get("HookResults") == [], (
        f"expected no Hook results for a target with no Hook invocations, got {list_resp}"
    )

    fabricated_hook_result_id = str(uuid.uuid4())
    get_error = _client_error(
        lambda: cfn.get_hook_result(HookResultId=fabricated_hook_result_id)
    )
    # The wire error Code drops the SDK shape's "Exception" suffix, as GeneratedTemplateNotFound does.
    assert get_error.get("Code") == "HookResultNotFound", (
        f"GetHookResult for an unknown HookResultId should report HookResultNotFound, "
        f"got {get_error!r}"
    )
    assert get_error.get("Message") == "The hook result was not found.", (
        f"expected message 'The hook result was not found.', got {get_error!r}"
    )


def _safe_delete_stack(cfn, stack_name) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _safe_delete_change_set(cfn, stack_name, cs_name) -> None:
    try:
        cfn.delete_change_set(StackName=stack_name, ChangeSetName=cs_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("ChangeSetNotFound",) or
            (exc.response["Error"]["Code"] == "ValidationError"
             and "does not exist" in exc.response["Error"].get("Message", ""))
        ):
            raise


def _wait_stack_status(
    cfn, stack_name, terminal_statuses, timeout_s=180.0, interval_s=5.0
):
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal_statuses:
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {stack_name} did not reach {terminal_statuses}, last={status}"
            )
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s; last value={result!r}"
            )
        time.sleep(interval_s)
        result = probe()
    return result


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
