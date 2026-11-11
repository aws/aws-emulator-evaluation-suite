"""abac-resource-tag-must-match-principal-tag-on-a-real-signed-call."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "abac-resource-tag-must-match-principal-tag-on-a-real-signed-call"
GROUP = "policy_simulation"
SERVICES = ["iam"]

_TAG_KEY = "project"
_ALPHA = "sim2real-alpha"
_BETA = "sim2real-beta"
_POLICY_NAME = "sim2real-behav-abac-tag-match"
_MARK = [{"Key": "sim2real", "Value": CHECK}]


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _denial_message(fn):
    """Error.Message of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Message") or ""
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


# An implicit-deny AccessDenied ends with a pointer to a server-minted, per-request authorization
# id, given twice (in a console URL and on its own); every other character is pinned.
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


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """One policy comparing iam:ResourceTag to ${aws:PrincipalTag} allows a signed call on the
    matching resource and denies it on a sibling with AccessDenied and the exact message;
    re-tagging the caller swaps both."""
    iam = ctx.client("iam")

    caller = ctx.unique_name("sim2real-abac-caller-")
    iam.create_user(UserName=caller, Path="/", Tags=_MARK)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=caller))
    caller_arn = iam.get_user(UserName=caller)["User"]["Arn"]

    match_user = ctx.unique_name("sim2real-abac-match-")
    iam.create_user(UserName=match_user, Path="/", Tags=_MARK + [{"Key": _TAG_KEY, "Value": _ALPHA}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=match_user))
    match_arn = iam.get_user(UserName=match_user)["User"]["Arn"]

    other_user = ctx.unique_name("sim2real-abac-other-")
    iam.create_user(UserName=other_user, Path="/", Tags=_MARK + [{"Key": _TAG_KEY, "Value": _BETA}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=other_user))
    other_arn = iam.get_user(UserName=other_user)["User"]["Arn"]

    # Both targets carry the tag key; only the VALUE differs, so a missing tag cannot pass as ABAC.
    assert _tags_of(iam, match_user).get(_TAG_KEY) == _ALPHA, (
        f"the matching target must carry {_TAG_KEY}={_ALPHA!r} before its access is probed; the "
        f"paginated tag list reports {_tags_of(iam, match_user)!r}"
    )
    assert _tags_of(iam, other_user).get(_TAG_KEY) == _BETA, (
        f"the sibling target must carry {_TAG_KEY}={_BETA!r} so the ONLY difference between the two "
        f"requests is the resource tag value; the paginated tag list reports "
        f"{_tags_of(iam, other_user)!r}"
    )

    iam.tag_user(UserName=caller, Tags=[{"Key": _TAG_KEY, "Value": _ALPHA}])

    # Both target ARNs are named, so only the Condition separates them. The unconditioned
    # iam:ListUserTags grant is a propagation control independent of the claim under test.
    iam.put_user_policy(
        UserName=caller,
        PolicyName=_POLICY_NAME,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "UnconditionedProbe",
                    "Effect": "Allow",
                    "Action": "iam:ListUserTags",
                    "Resource": [match_arn, other_arn],
                },
                {
                    "Sid": "AbacScoped",
                    "Effect": "Allow",
                    "Action": "iam:ListAccessKeys",
                    "Resource": [match_arn, other_arn],
                    "Condition": {
                        "StringEquals": {
                            f"iam:ResourceTag/{_TAG_KEY}": f"${{aws:PrincipalTag/{_TAG_KEY}}}"
                        }
                    },
                },
            ],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=caller, PolicyName=_POLICY_NAME))

    key = iam.create_access_key(UserName=caller)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=caller, AccessKeyId=key["AccessKeyId"]))
    as_caller = _signing_as(ctx, "iam", key)

    # IAM reports neither the key nor the policy as effective, so poll the unconditioned grant.
    ready = _poll(
        lambda: _outcome(lambda: as_caller.list_user_tags(UserName=match_user)),
        lambda o: o == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the unconditioned iam:ListUserTags grant becomes effective for the minted key",
    )
    assert ready == "OK", (
        f"the unconditioned grant must work before the ABAC-conditioned action is probed, or a "
        f"refusal below would mean nothing; expected 'OK', got {ready!r}"
    )

    allowed = _poll(
        lambda: _outcome(lambda: as_caller.list_access_keys(UserName=match_user)),
        lambda o: o == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description=(
            f"the ABAC Condition resolves to {_ALPHA!r} on both sides and permits the real signed "
            "iam:ListAccessKeys"
        ),
    )
    assert allowed == "OK", (
        f"the target's {_TAG_KEY} tag equals the caller's {_TAG_KEY} tag ({_ALPHA!r}), so the real "
        f"signed iam:ListAccessKeys must succeed; expected 'OK', got {allowed!r}"
    )

    # IAM appends a per-request authorization id (and a console URL carrying it) to this
    # denial, so the message is matched exactly except for that id.
    denied = _rejected_code(lambda: as_caller.list_access_keys(UserName=other_user))
    denied_msg = _denial_message(lambda: as_caller.list_access_keys(UserName=other_user))
    assert "is not authorized to perform: iam:ListAccessKeys" in denied_msg, (
        f"the denial must name the refused action iam:ListAccessKeys; got {denied_msg!r}"
    )
    assert denied == "AccessDenied", (
        f"the sibling target's {_TAG_KEY} tag is {_BETA!r} and the caller's is {_ALPHA!r}, so the "
        f"StringEquals Condition is not satisfied and the identical real signed call must be "
        f"refused with exactly AccessDenied; got {denied!r} -- an emulator that stores tags and "
        f"Conditions without joining them over-permits here"
    )
    assert denied_msg == _expected_denial(denied_msg, (
        f"User: {caller_arn} is not authorized to perform: iam:ListAccessKeys on resource: user "
        f"{other_user} because no identity-based policy allows the iam:ListAccessKeys action"
    )), (
        f"expected the exact AccessDenied message AWS returns, got {denied_msg!r}"
    )

    # The refusal is authorization, not absence: the admin can read the same resource.
    admin_view = iam.list_access_keys(UserName=other_user)
    assert "AccessKeyMetadata" in admin_view, (
        f"the sibling resource must be readable by an authorized principal, or the AccessDenied "
        f"above would be about a missing resource rather than a tag mismatch; ListAccessKeys "
        f"returned keys {sorted(admin_view)!r}"
    )

    # Re-tag the caller only; both outcomes must swap, so the variable is expanded per request.
    iam.tag_user(UserName=caller, Tags=[{"Key": _TAG_KEY, "Value": _BETA}])
    assert _tags_of(iam, caller).get(_TAG_KEY) == _BETA, (
        f"the caller's own tag must observably be {_BETA!r} before its effect is asserted; the "
        f"paginated tag list reports {_tags_of(iam, caller)!r}"
    )

    swapped_in = _poll(
        lambda: _outcome(lambda: as_caller.list_access_keys(UserName=other_user)),
        lambda o: o == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description=(
            "re-tagging the caller makes the PREVIOUSLY REFUSED sibling resource accessible"
        ),
    )
    assert swapped_in == "OK", (
        f"after the caller's {_TAG_KEY} tag became {_BETA!r}, the sibling resource's tag matches and "
        f"the call that was AccessDenied moments ago must now succeed; expected 'OK', got "
        f"{swapped_in!r}"
    )
    swapped_out = _poll(
        lambda: _outcome(lambda: as_caller.list_access_keys(UserName=match_user)),
        lambda o: o == "AccessDenied",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="re-tagging the caller REVOKES access to the formerly matching resource",
    )
    assert swapped_out == "AccessDenied", (
        f"the caller's tag is now {_BETA!r} and the formerly matching target's is {_ALPHA!r}, so the "
        f"call that succeeded moments ago must now be refused with exactly AccessDenied; got "
        f"{swapped_out!r} -- an emulator that caches the first decision per (principal, resource) "
        f"fails here"
    )
    swapped_msg = _denial_message(lambda: as_caller.list_access_keys(UserName=match_user))
    assert swapped_msg == _expected_denial(swapped_msg, (
        f"User: {caller_arn} is not authorized to perform: iam:ListAccessKeys on resource: user "
        f"{match_user} because no identity-based policy allows the iam:ListAccessKeys action"
    )), (
        f"expected the exact AccessDenied message AWS returns, got {swapped_msg!r}"
    )

    iam.tag_user(UserName=caller, Tags=[{"Key": _TAG_KEY, "Value": _ALPHA}])
    restored = _poll(
        lambda: _outcome(lambda: as_caller.list_access_keys(UserName=match_user)),
        lambda o: o == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="restoring the caller's tag restores access to the matching resource",
    )
    assert restored == "OK", (
        f"restoring the caller's {_TAG_KEY} tag to {_ALPHA!r} must restore the grant, proving the "
        f"denial was the tag comparison's doing; expected 'OK', got {restored!r}"
    )

    # SimulatePrincipalPolicy never reads a resource's live tags, so both tags go in as context.
    for value, expected in ((_ALPHA, "allowed"), (_BETA, "implicitDeny")):
        verdict = _simulated(iam, caller_arn, match_arn, _TAG_KEY, value, _ALPHA)
        assert verdict == expected, (
            f"with aws:PrincipalTag/{_TAG_KEY}={value!r} and iam:ResourceTag/{_TAG_KEY}={_ALPHA!r} "
            f"supplied as context, the simulator must say {expected!r} -- agreeing with the "
            f"enforcement path, which already produced that outcome for the same pairing; got "
            f"{verdict!r}"
        )


def _outcome(fn):
    """``"OK"`` on success, else the AWS error code."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"
    return "OK"


def _rejected_code(fn):
    """The AWS error code of a call real AWS MUST refuse; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded poll that RAISES on timeout.

    IAM propagates credentials, policies and tags eventually and reports none of them as effective.
    """
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _signing_as(ctx, service, key):
    """A client for ``service`` signing as the principal that owns ``key``, on the same endpoint."""
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )


def _tags_of(iam, user):
    """Every tag on the user, across all pages."""
    out = {}
    for page in iam.get_paginator("list_user_tags").paginate(UserName=user):
        for t in page["Tags"]:
            out[t["Key"]] = t["Value"]
    return out


def _simulated(iam, source_arn, resource_arn, tag_key, principal_tag_value, resource_tag_value):
    """The simulator's EvalDecision with both the principal and resource tag as context.

    SimulatePrincipalPolicy never queries live resource tags; without iam:ResourceTag it denies.
    """
    results = iam.simulate_principal_policy(
        PolicySourceArn=source_arn,
        ActionNames=["iam:ListAccessKeys"],
        ResourceArns=[resource_arn],
        ContextEntries=[
            {
                "ContextKeyName": f"aws:PrincipalTag/{tag_key}",
                "ContextKeyValues": [principal_tag_value],
                "ContextKeyType": "string",
            },
            {
                "ContextKeyName": f"iam:ResourceTag/{tag_key}",
                "ContextKeyValues": [resource_tag_value],
                "ContextKeyType": "string",
            },
        ],
    )["EvaluationResults"]
    assert results, (
        "SimulatePrincipalPolicy must return an evaluation result for the one action requested; "
        "EvaluationResults was empty"
    )
    return results[0]["EvalDecision"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
