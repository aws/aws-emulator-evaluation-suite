"""get-template-stages."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-template-stages"
GROUP = 'template'
SERVICES = ['cloudformation']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTemplate serves both the Original and Processed template stages for a deployed
    stack, and the two genuinely differ when the template carries a transform: Original is
    the bytes submitted; Processed is what CloudFormation expanded them into."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-cfn-stages-")
    topic_name = ctx.unique_name("sim2real-behav-cfn-topic-")
    tmpl = _sns_topic_template(topic_name, display_name="staged")
    cfn.create_stack(StackName=name, TemplateBody=tmpl, Capabilities=["CAPABILITY_AUTO_EXPAND"])
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, name))
    stack = _wait_stack_status(cfn, name)
    assert stack.get("StackStatus") == "CREATE_COMPLETE", stack.get("StackStatus")

    original = cfn.get_template(StackName=name, TemplateStage="Original")
    processed = cfn.get_template(StackName=name, TemplateStage="Processed")
    assert topic_name in str(original["TemplateBody"])
    assert topic_name in str(processed["TemplateBody"])
    assert "Original" in original.get("StagesAvailable", []), original.get("StagesAvailable")

    # AWS::LanguageExtensions expands Fn::ToJsonString at transform time, so the two stages
    # are provably different bodies, not just two reads of the same one.
    assert "Fn::ToJsonString" in str(original["TemplateBody"]), original["TemplateBody"]
    assert "Fn::ToJsonString" not in str(processed["TemplateBody"]), processed["TemplateBody"]


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
    props["Tags"] = [{"Key": "sim2real-behav-check", "Value": "get-template-stages"}]
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Transform": "AWS::LanguageExtensions",
            "Resources": {"MyTopic": {"Type": "AWS::SNS::Topic", "Properties": props}},
            "Outputs": {
                "TopicArnOutput": {"Value": {"Ref": "MyTopic"}},
                "TopicPropsJson": {"Value": {"Fn::ToJsonString": props}},
            },
        }
    )


def _describe_stack(cfn, name):
    stacks = cfn.describe_stacks(StackName=name).get("Stacks", [])
    assert stacks, f"stack {name} not found"
    return stacks[0]


def _wait_stack_status(cfn, name, timeout_s=180, interval_s=3):
    """Poll DescribeStacks until the stack reaches any terminal status."""
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
