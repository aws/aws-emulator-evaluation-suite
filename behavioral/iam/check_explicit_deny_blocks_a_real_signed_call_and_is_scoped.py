"""explicit-deny-blocks-a-real-signed-call-and-is-scoped."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "explicit-deny-blocks-a-real-signed-call-and-is-scoped"
GROUP = 'policy_simulation'
SERVICES = ['iam']

_PROPAGATION = frozenset({"InvalidClientTokenId", "SignatureDoesNotMatch"})
_ALLOW = "sim2real-behav-deny-allow-both"
_DENY = "sim2real-behav-deny-getuser"


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


def _drop_deny(iam, user):
    """Teardown-only: the body deletes this policy itself, so tolerate it already being gone."""
    try:
        iam.delete_user_policy(UserName=user, PolicyName=_DENY)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _denial_message(fn):
    """Error.Message of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Message") or ""
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c7")
def run(ctx) -> None:
    """An explicit Deny on iam:GetUser makes that real signed call fail with AccessDenied and the
    exact message while the allowed sibling call keeps working and the simulator reports explicitDeny
    from the user policy; deleting the Deny restores the call."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-deny-user-")

    iam.create_user(UserName=user, Path="/")
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    iam.put_user_policy(
        UserName=user,
        PolicyName=_ALLOW,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:GetUser", "iam:ListAccessKeys"],
                "Resource": user_arn,
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=_ALLOW))

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"])
    )
    as_user = ctx.client(
        "iam",
        creds={"aws_access_key_id": key["AccessKeyId"], "aws_secret_access_key": key["SecretAccessKey"]},
    )

    # --- Positive control, captured BEFORE anything is broken. IAM replicates the key AND the
    #     grant per-replica and reports neither as effective, so each leg that expects a fresh grant
    #     to work is a bounded poll on that success; it raises rather than skipping on non-
    #     convergence. A single shot here flakes -- a replica holding the key can still lack the
    #     policy.
    before_get = _poll(
        lambda: _error_code(lambda: as_user.get_user(UserName=user)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the Allow becomes effective for iam:GetUser on a real signed call",
    )
    assert before_get == "UNEXPECTED_SUCCESS", (
        "with only the Allow in place the real signed GetUser must succeed; got "
        f"{before_get!r} -- the control failed, so nothing below would be interpretable"
    )
    before_list = _poll(
        lambda: _error_code(lambda: as_user.list_access_keys(UserName=user)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the Allow becomes effective for iam:ListAccessKeys on a real signed call",
    )
    assert before_list == "UNEXPECTED_SUCCESS", (
        f"with only the Allow in place the real signed ListAccessKeys must succeed; got "
        f"{before_list!r}"
    )

    # --- Break exactly ONE thing: a second inline policy that denies iam:GetUser and nothing else.
    iam.put_user_policy(
        UserName=user,
        PolicyName=_DENY,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Deny", "Action": "iam:GetUser", "Resource": user_arn},
            ],
        }),
    )
    ctx.on_cleanup(lambda: _drop_deny(iam, user))

    after_get = _poll(
        lambda: _error_code(lambda: as_user.get_user(UserName=user)),
        lambda c: c == "AccessDenied",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the explicit Deny takes effect on the real signed GetUser",
    )
    assert after_get == "AccessDenied", (
        "an explicit Deny naming iam:GetUser must refuse the real signed call with exactly "
        f"AccessDenied; got {after_get!r}"
    )
    denied_msg = _denial_message(lambda: as_user.get_user(UserName=user))
    assert "is not authorized to perform: iam:GetUser" in denied_msg, (
        f"the denial must name the refused action iam:GetUser; got {denied_msg!r}"
    )
    assert denied_msg == _expected_denial(denied_msg, (
        f"User: {user_arn} is not authorized to perform: iam:GetUser on resource: user {user} "
        "with an explicit deny in an identity-based policy"
    )), f"expected the exact AccessDenied message AWS returns, got {denied_msg!r}"

    # The Deny is SCOPED to the action it names -- an emulator that revokes everything fails here.
    # Bounded poll, not a single shot: this grant was already proven live above, so the only thing
    # this tolerates is replica lag, and it still raises if the sibling action never comes back.
    after_list = _poll(
        lambda: _error_code(lambda: as_user.list_access_keys(UserName=user)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the sibling action iam:ListAccessKeys is unaffected by the Deny",
    )
    assert after_list == "UNEXPECTED_SUCCESS", (
        "the Deny names iam:GetUser only, so iam:ListAccessKeys must still succeed for the same "
        f"principal; got {after_list!r} -- a Deny is not a blanket revoke"
    )

    # The simulator must agree, and must call it an EXPLICIT deny with the deny policy named.
    sim = _poll(
        lambda: _decisions(iam, user_arn, ["iam:GetUser"], [user_arn]),
        lambda d: d.get("iam:GetUser", {}).get("EvalDecision") == "explicitDeny",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the simulator reports explicitDeny for iam:GetUser",
    )
    assert sim["iam:GetUser"]["EvalDecision"] == "explicitDeny", (
        "with a Deny statement present the simulator must say 'explicitDeny', not 'implicitDeny'; "
        f"got {sim['iam:GetUser']['EvalDecision']!r}"
    )
    # A stored inline user policy is attributed with the composite id
    # "user_<UserName>_<PolicyName>", not the bare policy name.
    matched = sim["iam:GetUser"].get("MatchedStatements", [])
    sources = {s.get("SourcePolicyId") for s in matched}
    assert sources == {f"user_{user}_{_DENY}"}, (
        f"the deny must be attributed to the stored inline policy that carries it, and to nothing "
        f"else: expected {{{f'user_{user}_{_DENY}'!r}}}, got {sorted(s for s in sources if s)!r}"
    )
    types = {s.get("SourcePolicyType") for s in matched}
    assert types == {"IAM Policy"}, (
        f"an inline user policy must be attributed as SourcePolicyType 'IAM Policy'; got "
        f"{sorted(t for t in types if t)!r}"
    )

    # --- Reverse the one change: the effect must be reversible, so the middle state was caused by
    #     the Deny and not by drift.
    iam.delete_user_policy(UserName=user, PolicyName=_DENY)
    restored = _poll(
        lambda: _error_code(lambda: as_user.get_user(UserName=user)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="deleting the Deny restores the real signed GetUser",
    )
    assert restored == "UNEXPECTED_SUCCESS", (
        "deleting the Deny must restore the Allow's grant on the real signed call; got "
        f"{restored!r}"
    )


def _decisions(iam, source_arn, actions, resource_arns):
    results = iam.simulate_principal_policy(
        PolicySourceArn=source_arn, ActionNames=actions, ResourceArns=resource_arns
    )["EvaluationResults"]
    return {r["EvalActionName"]: r for r in results}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
