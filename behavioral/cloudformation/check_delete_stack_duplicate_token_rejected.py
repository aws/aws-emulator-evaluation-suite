"""delete-stack-duplicate-token-rejected."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "delete-stack-duplicate-token-rejected"
GROUP = "concurrency"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """DeleteStack during UPDATE_IN_PROGRESS is rejected with a fresh token (ValidationError) and with the
    update's own token (TokenAlreadyExistsException or ValidationError, each with its exact message); the
    stack stays UPDATE_IN_PROGRESS, and after the update completes DeleteStack succeeds."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-delrej-")
    ctx.on_cleanup(lambda: _cleanup_stack(cfn, stack_name))

    base_template = json.dumps({
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
    })
    stack_id = cfn.create_stack(StackName=stack_name, TemplateBody=base_template)["StackId"]
    _wait_stack_status(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=180)

    # A template whose update will sit in UPDATE_IN_PROGRESS until we signal
    # the wait condition ourselves, giving us a deterministic "another
    # operation is in flight" state to race against and a controlled way to
    # lift it again afterward.
    slow_template = json.dumps({
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {}},
            "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Wait": {
                "Type": "AWS::CloudFormation::WaitCondition",
                "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "300", "Count": 1},
            },
        },
    })
    update_token = ctx.unique_name("tok-upd-")
    cfn.update_stack(StackName=stack_name, TemplateBody=slow_template, ClientRequestToken=update_token)
    _wait_stack_status(cfn, stack_name, {"UPDATE_IN_PROGRESS"}, timeout_s=30)

    # Arm 1: reusing the in-flight update's own token. CloudFormation may run its token-collision check
    # or its state check first, so either specific rejection is accepted; any other error or an accepted
    # delete fails.
    code, msg = _client_error(
        lambda: cfn.delete_stack(StackName=stack_name, ClientRequestToken=update_token),
        "DeleteStack reusing the in-flight update's token",
    )
    busy_message = f"Stack [{stack_id}] cannot be deleted while in status UPDATE_IN_PROGRESS"
    reused_token_messages = {
        "TokenAlreadyExistsException": (
            f"The client request token {update_token} has already been used for this stack. "
            "Retry the request with a different client request token"
        ),
        "ValidationError": busy_message,
    }
    assert code in reused_token_messages, (
        f"expected TokenAlreadyExistsException or ValidationError, got {code!r}"
    )
    assert msg == reused_token_messages[code], (code, msg)

    # Arm 2: a brand-new token that was never used for anything. With no
    # token collision to report, the in-progress state itself is now what
    # blocks the delete.
    fresh_token = ctx.unique_name("tok-fresh-")
    code, msg = _client_error(
        lambda: cfn.delete_stack(StackName=stack_name, ClientRequestToken=fresh_token),
        "DeleteStack with a fresh token during an update",
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    assert msg == busy_message, msg

    # Independent read: neither rejected delete advanced the stack's state --
    # it should still be exactly where the update left it.
    unchanged = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert unchanged["StackStatus"] == "UPDATE_IN_PROGRESS", (
        f"rejected DeleteStack calls must leave the stack untouched, got {unchanged['StackStatus']!r}"
    )

    # Restore: signal the WaitCondition so the update completes, lifting the
    # in-flight state that blocked both delete attempts.
    handle_url = _get_handle_url(cfn, stack_name, timeout_s=60.0)
    _signal_handle(ctx, handle_url, ctx.unique_name("sig-"), timeout_s=60.0)
    _wait_stack_status(
        cfn, stack_name, {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE"}, timeout_s=180
    )

    # Now that no operation is in flight, a DeleteStack call must succeed
    # (a new token, since it's unknown whether CloudFormation's token ledger
    # considers arm 2's token "used" even though that call was rejected), and
    # an independent read must confirm the stack actually reaches
    # DELETE_COMPLETE.
    final_token = ctx.unique_name("tok-final-")
    cfn.delete_stack(StackName=stack_name, ClientRequestToken=final_token)
    _wait_deleted(cfn, stack_name, timeout_s=180)


def _client_error(fn, what):
    """Return (code, message) of the ClientError `fn` raises; raise AssertionError if it succeeds."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")


def _get_handle_url(cfn, stack_name, timeout_s):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            detail = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Handle")
            url = detail["StackResourceDetail"].get("PhysicalResourceId")
            if url:
                return url
        except ClientError as exc:
            last_err = exc
        time.sleep(2)
    raise AssertionError(f"WaitConditionHandle URL was not available within {timeout_s}s: {last_err}")


def _signal_handle(ctx, handle_url, unique_id, timeout_s):
    body = json.dumps({
        "Status": "SUCCESS",
        "Reason": "sim2real check signal",
        "UniqueId": unique_id,
        "Data": "signaled",
    }).encode("utf-8")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            # Presigned S3 PUT URLs are signature-sensitive about headers; send none
            # beyond an explicitly empty Content-Type, matching CloudFormation's
            # documented signaling instructions for WaitConditionHandle URLs.
            req = _routed_request(ctx, handle_url, data=body, method="PUT", headers={"Content-Type": ""})
            with urllib.request.urlopen(req, timeout=30) as resp:
                if 200 <= resp.status < 300:
                    return
                last_err = f"HTTP {resp.status}"
        except urllib.error.URLError as exc:
            last_err = exc
        time.sleep(2)
    raise AssertionError(f"could not signal WaitConditionHandle within {timeout_s}s: {last_err}")


def _wait_deleted(cfn, stack_name, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
            if not stacks:
                return
            last = stacks[0]["StackStatus"]
            if last == "DELETE_COMPLETE":
                return
            if last == "DELETE_FAILED":
                raise AssertionError(f"stack {stack_name} reached DELETE_FAILED after the restored delete")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach DELETE_COMPLETE within {timeout_s}s (last={last!r})")


def _wait_stack_status(cfn, stack_name, ok_statuses, timeout_s=180, interval_s=3):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        if not stacks:
            raise AssertionError(f"stack {stack_name} disappeared while waiting for {ok_statuses}")
        status = stacks[0]["StackStatus"]
        if status in ok_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached {ok_statuses}, last status={status}")


def _cleanup_stack(cfn, stack_name):
    try:
        cfn.cancel_update_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return
        if not stacks:
            return
        if not stacks[0]["StackStatus"].endswith("IN_PROGRESS"):
            break
        time.sleep(3)
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return
        if not stacks or stacks[0]["StackStatus"] == "DELETE_COMPLETE":
            return
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
