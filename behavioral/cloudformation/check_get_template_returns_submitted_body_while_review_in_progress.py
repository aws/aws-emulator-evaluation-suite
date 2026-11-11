"""get-template-returns-submitted-body-while-review-in-progress."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-template-returns-submitted-body-while-review-in-progress"
GROUP = "template"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTemplate(ChangeSetName=...) on a REVIEW_IN_PROGRESS stack returns the template
    submitted to its unexecuted change set; GetTemplate(StackName=...) alone returns an
    empty body instead."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-cfn-review-")
    cs_name = ctx.unique_name("sim2real-behav-cs-")
    topic_name = ctx.unique_name("sim2real-behav-cfn-topic-")
    tmpl = _topic_template(topic_name)

    resp = cfn.create_change_set(
        StackName=name,
        ChangeSetName=cs_name,
        TemplateBody=tmpl,
        ChangeSetType="CREATE",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, name))
    cs_arn = resp["Id"]

    cs = _poll_until(
        lambda: cfn.describe_change_set(ChangeSetName=cs_arn),
        lambda r: r.get("Status") in {"CREATE_COMPLETE", "FAILED"},
        timeout_s=120,
        interval_s=2,
        description="CREATE-type change set reaching a terminal status",
    )
    assert cs["Status"] == "CREATE_COMPLETE", (cs["Status"], cs.get("StatusReason"))

    stack = _describe_stack(cfn, name)
    assert stack["StackStatus"] == "REVIEW_IN_PROGRESS", stack["StackStatus"]
    resources = cfn.list_stack_resources(StackName=name)["StackResourceSummaries"]
    assert resources == [], f"a stack whose change set was never executed must hold no resources, got {resources!r}"

    expected = json.loads(tmpl)

    by_change_set = cfn.get_template(ChangeSetName=cs_arn)
    assert _parsed_body(by_change_set["TemplateBody"]) == expected, (
        f"GetTemplate(ChangeSetName=...) returned {by_change_set['TemplateBody']!r}, "
        f"expected the submitted template {expected!r}"
    )

    by_stack_name = cfn.get_template(StackName=name)
    assert by_stack_name["TemplateBody"] == "", (
        f"GetTemplate(StackName=...) on a REVIEW_IN_PROGRESS stack (no executed template yet) "
        f"returned {by_stack_name['TemplateBody']!r}, expected an empty body"
    )

    _delete_stack_quiet(cfn, name)
    got = _error(lambda: cfn.describe_stacks(StackName=name))
    assert got == ("ValidationError", f"Stack with id {name} does not exist"), (
        f"DescribeStacks after the in-band delete: {got!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _parsed_body(body):
    return json.loads(body) if isinstance(body, str) else body


def _topic_template(topic_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyTopic": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": topic_name}}
            },
            "Outputs": {"TopicArnOutput": {"Value": {"Ref": "MyTopic"}}},
        }
    )


def _describe_stack(cfn, name):
    stacks = cfn.describe_stacks(StackName=name).get("Stacks", [])
    assert stacks, f"stack {name} not found"
    return stacks[0]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_stack_quiet(cfn, name):
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=name)
    cfn.get_waiter("stack_delete_complete").wait(StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
