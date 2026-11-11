"""deny-notaction-complement-enforced-on-a-real-signed-call."""
from __future__ import annotations

import json
import re
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deny-notaction-complement-enforced-on-a-real-signed-call"
GROUP = "policy_simulation"
SERVICES = ["iam"]

_ALLOW = "sim2real-behav-notaction-allow"
_DENY = "sim2real-behav-notaction-deny"
_GRANTED = ["iam:GetUser", "iam:ListUserTags", "iam:ListAccessKeys"]
_EXEMPT = ["iam:GetUser", "iam:ListUserTags"]
_MARK = [{"Key": "sim2real", "Value": CHECK}]


def _denial_message(fn):
    """Error.Message of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Message") or ""
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


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


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """`NotAction` inside a Deny is evaluated as a COMPLEMENT on a real signed call: of three Allowed
    actions, the two the Deny's NotAction names keep working, the third is refused with
    AccessDenied and the exact message, and deleting the Deny restores it."""
    iam = ctx.client("iam")

    user = ctx.unique_name("sim2real-notact-user-")
    iam.create_user(UserName=user, Path="/", Tags=_MARK)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    # The Allow half never changes: every leg below moves only the Deny half, so the Allow can never
    # be the explanation for a difference in outcome.
    _put(
        iam,
        user,
        _ALLOW,
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "AllowThree", "Effect": "Allow", "Action": _GRANTED, "Resource": user_arn}
            ],
        },
    )
    ctx.on_cleanup(lambda: _drop_user_policy(iam, user, _ALLOW))

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))
    as_user = _signing_as(ctx, "iam", key)

    # --- Positive control, before any Deny exists: all three actions work. This is what makes the
    #     refusal below meaningful, and it is the beat a "rejects everything" target fails.
    for action, call in _CALLS.items():
        code = _poll(
            lambda c=call: _outcome(lambda: c(as_user, user)),
            lambda o: o == "OK",
            timeout_s=_budget_s(ctx, 90.0),
            interval_s=3,
            description=f"the Allow statement makes {action} effective for the minted key",
        )
        assert code == "OK", (
            f"{action} is in the Allow statement and no Deny exists yet, so the real signed call "
            f"must succeed; expected 'OK', got {code!r}"
        )

    # --- Break exactly one thing: add a Deny whose NotAction exempts two of the three.
    _put(
        iam,
        user,
        _DENY,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyEverythingElse",
                    "Effect": "Deny",
                    "NotAction": _EXEMPT,
                    "Resource": "*",
                }
            ],
        },
    )
    ctx.on_cleanup(lambda: _drop_user_policy(iam, user, _DENY))

    complement = "iam:ListAccessKeys"
    denied = _poll(
        lambda: _outcome(lambda: _CALLS[complement](as_user, user)),
        lambda o: o == "AccessDenied",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description=f"the Deny's NotAction complement refuses {complement}",
    )
    assert denied == "AccessDenied", (
        f"{complement} is Allowed by the same document but is NOT in the Deny's NotAction list, so "
        f"the complement catches it and the real signed call must be refused with exactly "
        f"AccessDenied; got {denied!r} -- an emulator that ignores NotAction over-permits here"
    )
    denied_msg = _denial_message(lambda: _CALLS[complement](as_user, user))
    assert denied_msg == _expected_denial(denied_msg, (
        f"User: {user_arn} is not authorized to perform: {complement} on resource: user {user} "
        "with an explicit deny in an identity-based policy"
    )), f"expected the exact AccessDenied message AWS returns, got {denied_msg!r}"

    # --- Twin control, in the same instant: the exempt actions are untouched. This is the leg that
    #     catches an evaluator that read NotAction as Action, or that applied the Deny to everything.
    for action in _EXEMPT:
        code = _outcome(lambda a=action: _CALLS[a](as_user, user))
        assert code == "OK", (
            f"{action} IS in the Deny's NotAction list, so the Deny does not apply to it and the real "
            f"signed call must still succeed while {complement} is refused; expected 'OK', got "
            f"{code!r} -- an emulator that treats NotAction as Action inverts exactly here"
        )

    # --- Restore: delete only the Deny. The refused action must come back, so the refusal was the
    #     complement's doing and not a state the account fell into.
    iam.delete_user_policy(UserName=user, PolicyName=_DENY)
    remaining = [
        n
        for page in iam.get_paginator("list_user_policies").paginate(UserName=user)
        for n in page["PolicyNames"]
    ]
    assert remaining == [_ALLOW], (
        f"only the Deny may be gone -- the Allow statement must survive untouched, or the restore "
        f"proves nothing; expected [{_ALLOW!r}], the paginated ListUserPolicies reports {remaining!r}"
    )
    restored = _poll(
        lambda: _outcome(lambda: _CALLS[complement](as_user, user)),
        lambda o: o == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description=f"deleting the Deny restores {complement}",
    )
    assert restored == "OK", (
        f"with the Deny deleted, the Allow alone must permit {complement} again; expected 'OK', got "
        f"{restored!r}"
    )

    # --- The simulator's verdict must agree with what the authorizer already did. Advisory, joined
    #     to the enforcement outcomes above rather than standing in for them.
    _put(
        iam,
        user,
        _DENY,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyEverythingElse",
                    "Effect": "Deny",
                    "NotAction": _EXEMPT,
                    "Resource": "*",
                }
            ],
        },
    )
    verdicts = _simulated(iam, user_arn, user_arn, _GRANTED)
    assert verdicts[complement] == "explicitDeny", (
        f"the complement action is caught by a Deny statement, so the simulator must report "
        f"'explicitDeny' -- not 'implicitDeny', which would mean it never saw the Deny at all; got "
        f"{verdicts[complement]!r}"
    )
    for action in _EXEMPT:
        assert verdicts[action] == "allowed", (
            f"{action} is exempted by NotAction, so the simulator must report 'allowed', agreeing "
            f"with the real signed call that already succeeded; got {verdicts[action]!r}"
        )


# ===== helpers =====
_CALLS = {
    "iam:GetUser": lambda client, user: client.get_user(UserName=user),
    "iam:ListUserTags": lambda client, user: client.list_user_tags(UserName=user),
    "iam:ListAccessKeys": lambda client, user: client.list_access_keys(UserName=user),
}


def _outcome(fn):
    """``"OK"`` on success, else the AWS error code.

    ``"OK"`` is a truthy sentinel no AWS error code can equal, and every caller either feeds it to
    ``_poll`` (which RAISES on timeout, so a target that never converges cannot pass) or asserts it
    against an exact expected value.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"
    return "OK"


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry with a deadline. RAISES on timeout -- never returns its last value on failure."""
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
    """A client for ``service`` signing as the principal that owns ``key``.

    ``ctx.client(..., creds=...)`` is the engine's re-signing idiom: it keeps THIS target's
    endpoint, region and TLS settings, so the second hop can never reach real AWS by accident.
    """
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )


def _put(iam, user, policy_name, document):
    """Write one inline policy and read the stored document back through a different operation."""
    iam.put_user_policy(
        UserName=user, PolicyName=policy_name, PolicyDocument=json.dumps(document)
    )
    stored = iam.get_user_policy(UserName=user, PolicyName=policy_name)["PolicyDocument"]
    if isinstance(stored, str):
        stored = json.loads(urllib.parse.unquote(stored))
    assert stored["Statement"][0]["Sid"] == document["Statement"][0]["Sid"], (
        f"the stored inline policy must be the one just written before its enforcement is probed: "
        f"expected Sid {document['Statement'][0]['Sid']!r}, GetUserPolicy returned {stored!r}"
    )
    if "NotAction" in document["Statement"][0]:
        assert stored["Statement"][0].get("NotAction") == document["Statement"][0]["NotAction"], (
            f"the NotAction element must survive the round trip verbatim, or the enforcement legs "
            f"are probing a different document: expected "
            f"{document['Statement'][0]['NotAction']!r}, got "
            f"{stored['Statement'][0].get('NotAction')!r}"
        )


def _simulated(iam, source_arn, resource_arn, actions):
    """{action: EvalDecision} from SimulatePrincipalPolicy -- advisory, never enforcement."""
    results = iam.simulate_principal_policy(
        PolicySourceArn=source_arn, ActionNames=list(actions), ResourceArns=[resource_arn]
    )["EvaluationResults"]
    out = {r["EvalActionName"]: r["EvalDecision"] for r in results}
    missing = sorted(set(actions) - set(out))
    assert not missing, (
        f"SimulatePrincipalPolicy must return a verdict for every action requested; missing "
        f"{missing!r} from {sorted(out)!r}"
    )
    return out


def _drop_user_policy(iam, user, policy_name):
    """Teardown-only: tolerate the inline policy already being absent. Scoped to this one name."""
    try:
        iam.delete_user_policy(UserName=user, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
