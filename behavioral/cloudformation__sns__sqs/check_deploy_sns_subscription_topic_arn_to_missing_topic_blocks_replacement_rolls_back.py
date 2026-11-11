"""deploy-sns-subscription-topic-arn-to-missing-topic-blocks-replacement-rolls-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sns-subscription-topic-arn-to-missing-topic-blocks-replacement-rolls-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns", "sqs"]

#: A stack transition here takes seconds to a few minutes; the bound only stops a hung poll.
_DEADLINE_S = 600.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

# A resource-handler failure reason carries a per-request id and token, masked here, and may
# carry the SDK's attempt count, a retry detail that is dropped.
_MASKS = (
    (re.compile(r"Request ID: [^)]*\)"), "Request ID: <id>)"),
    (re.compile(r" \(SDK Attempt Count: \d+\)"), ""),
    (re.compile(r"\(RequestToken: [^,]*, "), "(RequestToken: <token>, "),
)


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Pointing a subscription's TopicArn (a create-only change) at a topic that does not exist
    fails the replacement's create step and rolls back, leaving the original subscription
    untouched; the same change onto a real topic succeeds and replaces it.
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")

    missing_topic_name = ctx.unique_name("sim2real-behav-cfnrepl-snsneg-missing-")
    stack_name = ctx.unique_name("sim2real-behav-cfnrepl-snsneg-")

    stack_id = _create(ctx, cfn, stack_name, _template())
    missing_topic_arn = f"arn:{stack_id.split(':')[1]}:sns:{ctx.region}:{ctx.account}:{missing_topic_name}"
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", (
        f"create ended {_stack(cfn, stack_id)!r}"
    )

    old_sub_arn = _physical_id(cfn, stack_id, "Sub")
    topic_a_arn = _outputs(cfn, stack_id)["TopicAArn"]
    sub_before = sns.get_subscription_attributes(SubscriptionArn=old_sub_arn)["Attributes"]
    assert sub_before["TopicArn"] == topic_a_arn, sub_before

    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(topic_arn=missing_topic_arn))
    status = _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S))
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"pointing at a missing topic must roll back, got {status!r}: {_stack(cfn, stack_id)!r}"
    )

    rows = [
        (status, _mask(reason), physical)
        for status, reason, physical in _rows_for(
            _events(cfn, stack_id)[before:], "Sub", "PhysicalResourceId"
        )
    ]
    failed_reason = (
        'Resource handler returned message: "Topic does not exist (Service: Sns, Status Code: 404, '
        'Request ID: <id>)" (RequestToken: <token>, HandlerErrorCode: NotFound)'
    )
    assert _in_order(rows, [
        ("UPDATE_IN_PROGRESS",
         "Requested update requires the creation of a new physical resource; hence creating one.",
         old_sub_arn),
        ("UPDATE_FAILED", failed_reason, old_sub_arn),
        ("UPDATE_COMPLETE", None, old_sub_arn),
    ]), (
        "Sub must report the replacement, fail it with the NotFound reason and roll back to the "
        f"original SubscriptionArn, in that order: {rows!r}"
    )
    original_deletes = [r for r in rows if r[0].startswith("DELETE_") and r[2] == old_sub_arn]
    assert original_deletes == [], f"the rollback never deletes the original: {original_deletes!r}"

    sub_after = sns.get_subscription_attributes(SubscriptionArn=old_sub_arn)["Attributes"]
    assert sub_after == sub_before, (
        f"the original subscription must survive a failed replacement unchanged: "
        f"{sub_before!r} -> {sub_after!r}"
    )

    # Positive control: the same TopicArn change onto a real topic succeeds and replaces it.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(topic_arn={"Ref": "TopicB"}))
    status = _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S))
    assert status == "UPDATE_COMPLETE", f"the unblocked TopicArn change must succeed, got {status!r}"

    new_sub_arn = _physical_id(cfn, stack_id, "Sub")
    assert new_sub_arn != old_sub_arn, (
        f"the successful replacement must mint a new SubscriptionArn, still {old_sub_arn!r}"
    )
    topic_b_arn = _outputs(cfn, stack_id)["TopicBArn"]
    sub_new = sns.get_subscription_attributes(SubscriptionArn=new_sub_arn)["Attributes"]
    assert sub_new["TopicArn"] == topic_b_arn, sub_new
    gone_code, gone_message = _error(lambda: sns.get_subscription_attributes(SubscriptionArn=old_sub_arn))
    assert (gone_code, gone_message) == ("NotFound", "Subscription does not exist"), (
        f"the successful replacement must remove the old subscription, got {(gone_code, gone_message)!r}"
    )


def _template(topic_arn=None) -> str:
    """Both topics always exist; only Sub's TopicArn property (and so what it targets) varies."""
    sub_topic_arn = topic_arn if topic_arn is not None else {"Ref": "TopicA"}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TopicA": {"Type": "AWS::SNS::Topic", "Properties": {"Tags": _TAGS}},
            "TopicB": {"Type": "AWS::SNS::Topic", "Properties": {"Tags": _TAGS}},
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": _TAGS}},
            # TopicArn is create-only for AWS::SNS::Subscription -> changing it replaces.
            "Sub": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {
                    "TopicArn": sub_topic_arn,
                    "Protocol": "sqs",
                    "Endpoint": {"Fn::GetAtt": ["Queue", "Arn"]},
                },
            },
        },
        "Outputs": {
            "TopicAArn": {"Value": {"Ref": "TopicA"}},
            "TopicBArn": {"Value": {"Ref": "TopicB"}},
        },
    })


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only the resource's own
    not_found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _cap(ctx, own_s: float, margin_s: float = 15.0) -> float:
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _poll(probe, done, *, timeout_s: float = _DEADLINE_S, interval_s: float = 3.0, what: str = "condition"):
    """Call ``probe()`` until ``done(result)`` holds and return the result; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _error(fn) -> tuple[str, str]:
    """``(code, message)`` of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _outputs(cfn, stack_id: str) -> dict:
    return {o["OutputKey"]: o["OutputValue"] for o in _stack(cfn, stack_id).get("Outputs", [])}


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _settle(cfn, stack_id: str, timeout_s: float = _DEADLINE_S) -> str:
    """The stack's status once no operation is in progress on it."""
    return _poll(
        lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
        timeout_s=timeout_s, what=f"stack {stack_id} settled",
    )


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    status = _stack(cfn, stack_id)["StackStatus"]
    if status == "UPDATE_IN_PROGRESS":
        cfn.cancel_update_stack(StackName=stack_id)
    if status != "CREATE_IN_PROGRESS":
        status = _settle(cfn, stack_id)
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise RuntimeError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


def _create(ctx, cfn, name: str, body: str, **kw) -> str:
    """CreateStack with its delete registered at once; returns the StackId."""
    stack_id = cfn.create_stack(StackName=name, TemplateBody=body, Tags=_TAGS, **kw)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return stack_id


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _rows_for(events: list[dict], logical_id: str, *keys: str) -> list[tuple]:
    """``(ResourceStatus, ResourceStatusReason, *keys)`` for every event on ``logical_id``."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), *(e.get(k) for k in keys))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _mask(reason: str | None) -> str:
    """The status reason with its per-request values masked; '' when the row has none."""
    out = reason or ""
    for pattern, repl in _MASKS:
        out = pattern.sub(repl, out)
    return out


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """Whether every ``wanted`` row occurs in ``rows`` in that order; a None field matches any."""
    remaining = iter(rows)
    return all(
        any(all(w is None or w == v for w, v in zip(want, row)) for row in remaining)
        for want in wanted
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
