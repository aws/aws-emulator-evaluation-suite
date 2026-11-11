"""tags-propagate-and-update."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tags-propagate-and-update"
GROUP = 'tags'
SERVICES = ['cloudformation']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStack tags appear on DescribeStacks and UpdateStack's Tags replace them (not merged); after
    DeleteStack, DescribeStacks fails with ValidationError "Stack with id <name> does not exist" and
    UpdateStack with "Stack [<name>] does not exist"."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-cfn-tags-")
    topic_name = ctx.unique_name("sim2real-behav-cfn-topic-")
    tmpl = _sns_topic_template(topic_name)
    cfn.create_stack(
        StackName=name,
        TemplateBody=tmpl,
        Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, name))
    stack = _wait_stack_status(cfn, name)
    tag_map = {t["Key"]: t["Value"] for t in stack.get("Tags", [])}
    assert tag_map == {"env": "test", "owner": "fidelity"}, tag_map

    cfn.update_stack(
        StackName=name,
        TemplateBody=tmpl,
        Tags=[{"Key": "env", "Value": "prod"}],
    )
    updated = _wait_stack_status(cfn, name)
    updated_tag_map = {t["Key"]: t["Value"] for t in updated.get("Tags", [])}
    assert updated_tag_map == {"env": "prod"}, updated_tag_map

    cfn.delete_stack(StackName=name)
    not_found = _wait_for_name_not_found(cfn, name)
    expected_not_found = ("ValidationError", f"Stack with id {name} does not exist")
    assert not_found == expected_not_found, (
        f"deleted stack {name} should be unresolvable by name via DescribeStacks with "
        f"{expected_not_found!r}, got {not_found!r}"
    )
    reuse = _error(lambda: cfn.update_stack(StackName=name, TemplateBody=tmpl))
    expected_reuse = ("ValidationError", f"Stack [{name}] does not exist")
    assert reuse == expected_reuse, (
        f"UpdateStack on a deleted stack name should reject with {expected_reuse!r}, "
        f"got {reuse!r}"
    )


_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
}


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _sns_topic_template(topic_name, display_name=None) -> str:
    props = {"TopicName": topic_name}
    if display_name is not None:
        props["DisplayName"] = display_name
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"MyTopic": {"Type": "AWS::SNS::Topic", "Properties": props}},
            "Outputs": {"TopicArnOutput": {"Value": {"Ref": "MyTopic"}}},
        }
    )


def _describe_stack(cfn, name):
    stacks = cfn.describe_stacks(StackName=name).get("Stacks", [])
    assert stacks, f"stack {name} not found"
    return stacks[0]


def _wait_stack_status(cfn, name, timeout_s=180, interval_s=3):
    """Poll DescribeStacks until the stack reaches any terminal status.

    UpdateStack moves the stack to UPDATE_IN_PROGRESS before it returns, so calling this
    straight after an update does not read the pre-update terminal status back.
    """
    return _poll_until(
        lambda: _describe_stack(cfn, name),
        lambda stack: stack.get("StackStatus") in _TERMINAL_STACK_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"stack {name} reaching a terminal status",
    )


def _delete_stack_quiet(cfn, name):
    try:
        cfn.delete_stack(StackName=name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _error(fn):
    """(Error.Code, Error.Message) of the rejection fn() raises; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("expected a ClientError, call succeeded unexpectedly")


def _wait_for_name_not_found(cfn, name, timeout_s=120.0, interval_s=3.0):
    """Poll DescribeStacks-by-name until it rejects the now-deleted name, returning the
    error (code, message). DeleteStack leaves the stack visible (StackStatus DELETE_COMPLETE) for a
    window before name-based lookup stops resolving it, so a single read is not enough."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            cfn.describe_stacks(StackName=name)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"stack {name} still resolves by name via DescribeStacks after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
