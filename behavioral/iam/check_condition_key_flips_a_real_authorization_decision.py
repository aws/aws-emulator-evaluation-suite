"""condition-key-flips-a-real-authorization-decision."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-key-flips-a-real-authorization-decision"
GROUP = 'policy_simulation'
SERVICES = ['iam']

_PROPAGATION = frozenset({"InvalidClientTokenId", "SignatureDoesNotMatch"})
_CONDITIONED = "sim2real-behav-cond-tag-if-env-matches"
_MATCHING = "sim2real"
_VIOLATING = "production"


# An AccessDenied ends with a pointer to a server-minted, per-request authorization id, given
# twice (in a console URL and on its own); every other character is pinned.
_AUTHZ_TAIL = (
    r"\. Go to https://[a-z0-9-]+\.console\.aws\.amazon\.com/iam/home\?region=[a-z0-9-]+"
    r"#/authorization-details/(\w+) for complete details, or call the GetRequestAuthorizationDetails "
    r"API with the following authorization id: \1"
)


def _expected_denial(message, head):
    """``head`` followed by the authorization-details pointer that ends ``message``: the pointer's
    region and per-request authorization id are the only parts read back from it."""
    found = re.search(_AUTHZ_TAIL + r"\Z", message or "")
    return head + (found.group(0) if found else ". Go to <authorization-details pointer>")


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _error_code(fn):
    """The captured AWS error code, or a sentinel that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "UNEXPECTED_SUCCESS"


def _client_for_credentials(ctx, access_key_id, secret_access_key, service="iam"):
    """A client for ``service`` on this target, signing AS the minted principal."""
    return ctx.client(
        service,
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _tags_of(iam, user):
    """Every tag on the user, across all pages."""
    out = {}
    for page in iam.get_paginator("list_user_tags").paginate(UserName=user):
        for t in page.get("Tags", []):
            out[t["Key"]] = t["Value"]
    return out


def _decision_with_context(iam, source_arn, resource_arn, env_value):
    results = iam.simulate_principal_policy(
        PolicySourceArn=source_arn,
        ActionNames=["iam:TagUser"],
        ResourceArns=[resource_arn],
        ContextEntries=[{
            "ContextKeyName": "aws:RequestTag/env",
            "ContextKeyValues": [env_value],
            "ContextKeyType": "string",
        }],
    )["EvaluationResults"]
    return results[0]["EvalDecision"]


def _denial_message(fn):
    """Error.Message of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Message") or ""
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c7")
def run(ctx) -> None:
    """A StringEquals Condition on aws:RequestTag/env is evaluated against the real request:
    TagUser with the matching value succeeds; a different value gets AccessDenied with the exact
    message and writes nothing."""
    iam = ctx.client("iam")
    caller = ctx.unique_name("sim2real-behav-cond-caller-")
    target = ctx.unique_name("sim2real-behav-cond-target-")

    iam.create_user(UserName=caller, Path="/")
    ctx.on_cleanup(lambda: iam.delete_user(UserName=caller))
    caller_arn = iam.get_user(UserName=caller)["User"]["Arn"]

    iam.create_user(UserName=target, Path="/")
    ctx.on_cleanup(lambda: iam.delete_user(UserName=target))
    target_arn = iam.get_user(UserName=target)["User"]["Arn"]

    # iam:TagUser is conditioned on the tag value the REQUEST carries; iam:ListUserTags is not, so
    # credential replication can be established without depending on the conditioned action.
    iam.put_user_policy(
        UserName=caller,
        PolicyName=_CONDITIONED,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:TagUser",
                    "Resource": target_arn,
                    "Condition": {"StringEquals": {"aws:RequestTag/env": _MATCHING}},
                },
                {"Effect": "Allow", "Action": "iam:ListUserTags", "Resource": target_arn},
            ],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=caller, PolicyName=_CONDITIONED))

    key = iam.create_access_key(UserName=caller)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=caller, AccessKeyId=key["AccessKeyId"])
    )
    as_caller = _client_for_credentials(ctx, key["AccessKeyId"], key["SecretAccessKey"])

    # IAM reports neither the key nor the policy as effective, so poll the unconditioned grant.
    ready = _poll(
        lambda: _error_code(lambda: as_caller.list_user_tags(UserName=target)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the unconditioned iam:ListUserTags grant becomes effective for the minted key",
    )
    assert ready == "UNEXPECTED_SUCCESS", (
        f"the unconditioned iam:ListUserTags grant must work before the conditioned action is "
        f"probed; got {ready!r}"
    )

    satisfied = _poll(
        lambda: _error_code(
            lambda: as_caller.tag_user(
                UserName=target, Tags=[{"Key": "env", "Value": _MATCHING}]
            )
        ),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the conditioned iam:TagUser grant takes effect for the matching tag value",
    )
    ctx.on_cleanup(lambda: iam.untag_user(UserName=target, TagKeys=["env"]))
    assert satisfied == "UNEXPECTED_SUCCESS", (
        f"the Condition is satisfied by env={_MATCHING!r}, so the real signed TagUser must succeed; "
        f"got {satisfied!r}"
    )
    landed = _tags_of(iam, target)
    assert landed == {"env": _MATCHING}, (
        f"the permitted write must be observable with the exact value it carried: expected "
        f"{{'env': {_MATCHING!r}}}, the paginated tag list reports {landed!r}"
    )

    violated = _error_code(
        lambda: as_caller.tag_user(UserName=target, Tags=[{"Key": "env", "Value": _VIOLATING}])
    )
    violated_msg = _denial_message(
        lambda: as_caller.tag_user(UserName=target, Tags=[{"Key": "env", "Value": _VIOLATING}])
    )
    assert "is not authorized to perform: iam:TagUser" in violated_msg, (
        f"the denial must name the refused action iam:TagUser; got {violated_msg!r}"
    )
    assert violated_msg == _expected_denial(violated_msg, (
        f"User: {caller_arn} is not authorized to perform: iam:TagUser on resource: user {target} "
        "because no identity-based policy allows the iam:TagUser action"
    )), f"expected the exact AccessDenied message AWS returns, got {violated_msg!r}"
    assert violated == "AccessDenied", (
        f"env={_VIOLATING!r} fails the StringEquals Condition, so the identical real signed TagUser "
        f"must be refused with exactly AccessDenied; got {violated!r} -- an emulator that stores the "
        f"Condition without evaluating it over-permits here"
    )

    after = _tags_of(iam, target)
    assert after == {"env": _MATCHING}, (
        f"the rejected write must have had NO effect: expected the tag set unchanged at "
        f"{{'env': {_MATCHING!r}}}, got {after!r}"
    )
    assert _VIOLATING not in after.values(), (
        f"no tag may carry the rejected value {_VIOLATING!r}; the tag set is {after!r}"
    )

    # The simulator's decision must flip with the supplied context and agree with both outcomes.
    violating_decision = _decision_with_context(iam, caller_arn, target_arn, _VIOLATING)
    assert violating_decision == "implicitDeny", (
        f"an Allow whose Condition is not satisfied must not grant, so the simulator must say "
        f"'implicitDeny' for env={_VIOLATING!r}; got {violating_decision!r}"
    )
    matching_decision = _decision_with_context(iam, caller_arn, target_arn, _MATCHING)
    assert matching_decision == "allowed", (
        f"the simulator must say 'allowed' for env={_MATCHING!r}, agreeing with the real call that "
        f"already succeeded; got {matching_decision!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
