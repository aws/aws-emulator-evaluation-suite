"""cfn-iam-policy-no-principal-rejected-then-round-trips-attached-to-user."""

from __future__ import annotations

import json
import re
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-policy-no-principal-rejected-then-round-trips-attached-to-user"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam"]

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
    }
)
# The handler reports a per-attempt RequestToken that is minted by AWS and unknowable in advance;
# the surrounding text is the only part a check can pin down.
_REASON_RE = re.compile(
    r'^Resource handler returned message: "At least one of \[Groups,Roles,Users\] must be '
    r'non-empty\." \(RequestToken: ([0-9a-f-]{36}), HandlerErrorCode: InvalidRequest\)$'
)


_DELETE_TERMINAL = frozenset({"DELETE_COMPLETE", "DELETE_FAILED"})


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _stack_status(cfn, stack_id: str) -> str:
    """The stack's status read by StackId; the exact not-found pair reads as DELETE_COMPLETE."""
    try:
        return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == (
            "ValidationError",
            f"Stack with id {stack_id} does not exist",
        ):
            return "DELETE_COMPLETE"
        raise


def _wait_stack(ctx, cfn, stack_id: str, terminal=_TERMINAL, *, timeout_s: float = 240.0) -> str:
    """The stack's status once it is in ``terminal``, polled against a capped deadline."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _stack_status(cfn, stack_id)
        if last in terminal:
            return last
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"stack {stack_id!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"stack {stack_id!r} not in {sorted(terminal)} within {timeout_s}s (last={last!r})"
    )


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack whatever state it is in, and raise unless it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    status = _wait_stack(ctx, cfn, stack_id, _DELETE_TERMINAL, timeout_s=300.0)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} delete ended {status!r}")


def _failure_reason(cfn, stack_id: str, logical_id: str) -> str:
    """The ResourceStatusReason of ``logical_id``'s single CREATE_FAILED event, across all pages."""
    reasons = [
        event.get("ResourceStatusReason", "")
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
        for event in page["StackEvents"]
        if event["ResourceStatus"] == "CREATE_FAILED" and event["LogicalResourceId"] == logical_id
    ]
    assert len(reasons) == 1, (
        f"expected one CREATE_FAILED event for {logical_id!r}, got {reasons!r}"
    )
    return reasons[0]


def _doc(doc):
    """IAM echoes PolicyDocument as a URL-encoded JSON string on some calls, a dict on others."""
    return doc if isinstance(doc, dict) else json.loads(urllib.parse.unquote(doc))


def _policy_resource(policy_name: str, document: dict, *, users: list | None) -> dict:
    props = {"PolicyName": policy_name, "PolicyDocument": document}
    if users is not None:
        props["Users"] = users
    return {"Type": "AWS::IAM::Policy", "Properties": props}


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:deploy",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An AWS::IAM::Policy with no Groups, Roles or Users fails at create with the handler's own
    validation message and the stack rolls back; the same PolicyDocument attached via Users to a
    stack-created user deploys, and ListUserPolicies/GetUserPolicy reflect it exactly."""
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")

    document = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
    }
    policy_name = ctx.unique_name("sim2real-behav-iampol-")

    # The one thing broken: no Groups, Roles or Users at all.
    bad_stack_name = ctx.unique_name("sim2real-behav-iampolbad-stack-")
    bad_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"Policy": _policy_resource(policy_name, document, users=None)},
        }
    )
    bad_stack_id = cfn.create_stack(
        StackName=bad_stack_name,
        TemplateBody=bad_template,
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, bad_stack_id))
    bad_status = _wait_stack(ctx, cfn, bad_stack_id)
    assert bad_status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {bad_status!r}"
    reason = _failure_reason(cfn, bad_stack_id, "Policy")
    match = _REASON_RE.match(reason)
    assert match is not None, (
        f"the no-principal failure reason no longer has the shape this check knows: {reason!r}"
    )
    expected_reason = (
        'Resource handler returned message: "At least one of [Groups,Roles,Users] must be '
        'non-empty." '
        f"(RequestToken: {match.group(1)}, HandlerErrorCode: InvalidRequest)"
    )
    assert reason == expected_reason, f"expected {expected_reason!r}, got {reason!r}"

    # Positive control: the identical PolicyDocument, attached via Users to a stack-created user.
    good_stack_name = ctx.unique_name("sim2real-behav-iampolgood-stack-")
    user_name = ctx.unique_name("sim2real-behav-iampoluser-")
    good_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "User": {"Type": "AWS::IAM::User", "Properties": {"UserName": user_name}},
                "Policy": _policy_resource(policy_name, document, users=[{"Ref": "User"}]),
            },
        }
    )
    good_stack_id = cfn.create_stack(
        StackName=good_stack_name,
        TemplateBody=good_template,
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, good_stack_id))
    good_status = _wait_stack(ctx, cfn, good_stack_id)
    assert good_status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {good_status!r}"

    policy_names = iam.list_user_policies(UserName=user_name)["PolicyNames"]
    assert policy_names == [policy_name], (
        f"expected ListUserPolicies to report exactly [{policy_name!r}], got {policy_names!r}"
    )
    got_doc = _doc(
        iam.get_user_policy(UserName=user_name, PolicyName=policy_name)["PolicyDocument"]
    )
    assert got_doc == document, f"expected the exact stored document {document!r}, got {got_doc!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
