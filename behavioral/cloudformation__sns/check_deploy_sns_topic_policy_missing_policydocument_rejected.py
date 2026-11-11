"""deploy-sns-topic-policy-missing-policydocument-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sns-topic-policy-missing-policydocument-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}
_STACK_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)
_SID = "sim2real-control"


def _template(topic_name: str, *, with_document: bool) -> str:
    policy: dict = {"Topics": [{"Ref": "Topic"}]}
    if with_document:
        policy["PolicyDocument"] = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": _SID, "Effect": "Allow",
                "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
                "Action": "SNS:Publish", "Resource": {"Ref": "Topic"},
            }],
        }
    return json.dumps({
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": topic_name}},
            "Policy": {"Type": "AWS::SNS::TopicPolicy", "Properties": policy},
        }
    })


def _wait_terminal(cfn, stack_name: str, timeout_s: float = 180.0) -> str:
    """Poll DescribeStacks until the stack reaches a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state within "
                          f"{timeout_s}s (last={last!r})")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::SNS::TopicPolicy with no PolicyDocument fails pre-deployment property validation and
    creates no topic, while the same template with a PolicyDocument deploys and attaches it.
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")

    # Positive control: the identical template with a PolicyDocument, through CloudFormation.
    control_topic = ctx.unique_name("sim2real-behav-topicpol-ctrl-")
    control_arn = f"arn:aws:sns:{ctx.region}:{ctx.account}:{control_topic}"
    control_stack = ctx.unique_name("sim2real-behav-topicpol-ctrl-stack-")
    cfn.create_stack(StackName=control_stack, TemplateBody=_template(control_topic, with_document=True),
                     Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_stack(cfn, control_stack))
    status = _wait_terminal(cfn, control_stack)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    got_control = json.loads(sns.get_topic_attributes(TopicArn=control_arn)["Attributes"]["Policy"])
    assert [st.get("Sid") for st in got_control["Statement"]] == [_SID], (
        f"the control stack's topic policy reads back as {got_control!r}"
    )

    # The one thing broken: the same template without a PolicyDocument.
    topic_name = ctx.unique_name("sim2real-behav-topicpol-bad-")
    stack_name = ctx.unique_name("sim2real-behav-topicpol-bad-stack-")
    cfn.create_stack(StackName=stack_name, TemplateBody=_template(topic_name, with_document=False),
                     Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    status = _wait_terminal(cfn, stack_name)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    stack_failed_reasons = [
        e.get("ResourceStatusReason", "") for e in events
        if e.get("LogicalResourceId") == stack_name and e.get("ResourceStatus") == "CREATE_FAILED"
    ]
    assert stack_failed_reasons == [_STACK_REASON], (
        f"expected the stack's CREATE_FAILED reason to be {_STACK_REASON!r}, got {stack_failed_reasons!r}"
    )
    found = _validation_errors(cfn, stack_name)
    want = [(
        "Policy", "AWS::SNS::TopicPolicy", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        "Required property [PolicyDocument] not found", "/Resources/Policy/Properties",
    )]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"
    resources = cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    assert resources == [], (
        f"a stack rejected before provisioning must report no resources, got {resources!r}"
    )
    topic_arn = f"arn:aws:sns:{ctx.region}:{ctx.account}:{topic_name}"
    got = _error(lambda: sns.get_topic_attributes(TopicArn=topic_arn))
    assert got == ("NotFound", "Topic does not exist"), f"GetTopicAttributes on the rejected stack's topic: {got!r}"

    for name in (stack_name, control_stack):
        _delete_stack(cfn, name)
        got = _error(lambda name=name: cfn.describe_stacks(StackName=name))
        assert got == ("ValidationError", f"Stack with id {name} does not exist"), (
            f"DescribeStacks after the delete of {name}: {got!r}"
        )
    got = _error(lambda: sns.get_topic_attributes(TopicArn=control_arn))
    assert got == ("NotFound", "Topic does not exist"), (
        f"the control stack's topic after its stack delete: {got!r}"
    )


def _validation_errors(cfn, stack_name: str) -> list[tuple]:
    """``(logical id, type, name, status, mode, reason, path)`` of each VALIDATION_ERROR operation event."""
    out: list[tuple] = []
    kwargs = {"StackName": stack_name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend((e.get("LogicalResourceId"), e.get("ResourceType"), e.get("ValidationName"),
                    e.get("ValidationStatus"), e.get("ValidationFailureMode"), e.get("ValidationStatusReason"),
                    e.get("ValidationPath"))
                   for e in page["OperationEvents"] if e.get("EventType") == "VALIDATION_ERROR")
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _delete_stack(cfn, stack_name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
