"""deploy-cfn-sns-topic-invalid-tracingconfig-value-rolls-back-creating-nothing."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-sns-topic-invalid-tracingconfig-value-rolls-back-creating-nothing"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns"]

_STACK_CAP_S = 600.0
_POLL_S = 2.0

_NOT_FOUND = ("NotFound", "Topic does not exist")


def _template(topic_name: str, tracing_config: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Topic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": topic_name,
                    "TracingConfig": tracing_config,
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                },
            },
        },
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """A CloudFormation topic with an unmodelled TracingConfig value rolls the stack back and
    creates no topic; the same template with a valid value succeeds.

    Reference: https://docs.aws.amazon.com/sns/latest/dg/sns-active-tracing.html
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")

    bad_name = ctx.unique_name("sim2real-cfnbadtrc-")
    bad_stack = ctx.unique_name("sim2real-cfnbadtrc-stack-")
    bad_arn = f"arn:aws:sns:{ctx.region}:{ctx.account}:{bad_name}"
    bad_ref = {"stack": bad_stack}
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, bad_ref))

    # ---- 1. break exactly one thing: an unmodelled TracingConfig value
    bad_ref["stack"] = cfn.create_stack(
        StackName=bad_stack, TemplateBody=_template(bad_name, "Sampled"),
    )["StackId"]
    stack = _settle(ctx, cfn, bad_ref["stack"])
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"a stack whose only resource is an invalid topic must end ROLLBACK_COMPLETE, "
        f"got {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r})"
    )
    failures = [
        (e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, bad_ref["stack"])
        if e["LogicalResourceId"] == "Topic" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(failures) == 1, f"expected exactly one Topic CREATE_FAILED event, got {failures!r}"
    reason = failures[0][1] or ""
    assert "tracing config value: Sampled" in reason, (
        f"the CREATE_FAILED reason must name the rejected TracingConfig value, got {reason!r}"
    )

    # ---- 2. the effect is absent: no such topic was ever created
    got = _error(lambda: sns.get_topic_attributes(TopicArn=bad_arn))
    assert got == _NOT_FOUND, f"GetTopicAttributes for the never-created topic answered {got!r}"

    # ---- the exact fault CloudFormation's resource handler forwarded, read directly from SNS
    direct_name = ctx.unique_name("sim2real-cfnbadtrc-direct-")
    created: dict[str, str] = {}

    def _call_direct():
        resp = sns.create_topic(Name=direct_name, Attributes={"TracingConfig": "Sampled"})
        created["arn"] = resp["TopicArn"]
        ctx.on_cleanup(_teardown(lambda: sns.delete_topic(TopicArn=created["arn"])))
        return created["arn"]

    code, message = _error(_call_direct)
    assert (code, message) == (
        "InvalidParameter",
        "Invalid parameter: Attributes Reason: Invalid tracing config value: Sampled",
    ), f"CreateTopic with TracingConfig Sampled answered ({code!r}, {message!r})"

    # ---- 3. positive control: the same template with a modelled value succeeds
    good_name = ctx.unique_name("sim2real-cfngoodtrc-")
    good_stack = ctx.unique_name("sim2real-cfngoodtrc-stack-")
    good_arn = f"arn:aws:sns:{ctx.region}:{ctx.account}:{good_name}"
    good_ref = {"stack": good_stack}
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, good_ref))

    good_ref["stack"] = cfn.create_stack(
        StackName=good_stack, TemplateBody=_template(good_name, "Active"),
    )["StackId"]
    good = _settle(ctx, cfn, good_ref["stack"])
    assert good["StackStatus"] == "CREATE_COMPLETE", (
        f"the identical template with TracingConfig Active must succeed, got "
        f"{good['StackStatus']!r} ({good.get('StackStatusReason')!r})"
    )
    attrs = sns.get_topic_attributes(TopicArn=good_arn)["Attributes"]
    assert attrs.get("TracingConfig") == "Active", (
        f"the control topic's TracingConfig read back as {attrs.get('TracingConfig')!r}"
    )


# ===== helpers =====


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _budget_s(ctx, cap_s):
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s")
        time.sleep(_POLL_S)


def _events(cfn, stack_id: str) -> list[dict]:
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    stack = _settle(ctx, cfn, stack_id)
    if stack["StackStatus"] != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {stack['StackStatus']!r}")


def _teardown_stack(ctx, cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done."""
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(ctx, cfn, stack["StackId"])
    _delete_stack(ctx, cfn, stack["StackId"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
