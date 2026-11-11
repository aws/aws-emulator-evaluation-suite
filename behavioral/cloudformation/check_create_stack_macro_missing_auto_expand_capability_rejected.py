"""create-stack-macro-missing-auto-expand-capability-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-stack-macro-missing-auto-expand-capability-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps(
    {
        "Transform": "AWS::Serverless-2016-10-31",
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic"}},
    }
)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A template declaring a macro Transform is rejected with InsufficientCapabilitiesException
    when CAPABILITY_AUTO_EXPAND is not acknowledged -- the capability check can't be bypassed --
    while the identical template with the capability acknowledged creates successfully."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-cfn-automacro-")

    code, message = _error(lambda: cfn.create_stack(StackName=name, TemplateBody=_TEMPLATE))
    assert code == "InsufficientCapabilitiesException", f"expected InsufficientCapabilitiesException, got {code}"
    expected = "Requires capabilities : [CAPABILITY_AUTO_EXPAND]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # (b) effect absent: no stack was created for this name
    not_found_code, not_found_message = _error(lambda: cfn.describe_stacks(StackName=name))
    assert not_found_code == "ValidationError", f"expected stack-not-found ValidationError, got {not_found_code}"
    assert not_found_message == f"Stack with id {name} does not exist", (
        f"expected the exact stack-not-found message, got {not_found_message!r}"
    )

    # (c) positive control: same template, with the capability acknowledged, succeeds
    cfn.create_stack(
        StackName=name,
        TemplateBody=_TEMPLATE,
        Capabilities=["CAPABILITY_AUTO_EXPAND"],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_stack(ctx, name))
    _wait_stack_status(ctx, name, {"CREATE_COMPLETE"})

    # (d) terminal read at the destination: the macro-expanded Topic is a real,
    # live SNS resource -- not merely a stack that reports CREATE_COMPLETE.
    resources = cfn.describe_stack_resources(StackName=name)["StackResources"]
    topic_resources = [r for r in resources if r["LogicalResourceId"] == "Topic"]
    assert topic_resources, f"expected a Topic resource in stack {name}, got {resources}"
    topic_arn = topic_resources[0]["PhysicalResourceId"]
    sns = ctx.client("sns")
    attrs = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    assert attrs["TopicArn"] == topic_arn, f"expected live topic {topic_arn}, got {attrs.get('TopicArn')}"


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe_delete_stack(ctx, name):
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _wait_stack_status(ctx, name, terminal_statuses, timeout_s=180.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=name)["Stacks"]
        last = stacks[0]["StackStatus"]
        if last in terminal_statuses:
            return last
        if last.endswith("FAILED") or "ROLLBACK" in last:
            raise AssertionError(f"stack {name} entered unexpected status {last}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {name} never reached {terminal_statuses}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
