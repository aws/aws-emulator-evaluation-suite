"""op-contract-listUsers-missing-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listUsers-missing-permission-denied"
GROUP = "error-semantics"
SERVICES = ["iam"]

_ALLOW = "sim2real-list-users-deny-allow-both"
_DENY = "sim2real-list-users-deny-list-users"


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListUsers pages include a new user; an explicit Deny makes another user's real signed
    ListUsers fail with AccessDenied and the exact message while iam:ListRoles still works,
    the simulator reports explicitDeny, and removing the Deny restores the call."""
    iam = ctx.client("iam")

    # success-path contract: create a real user and find it via pagination in ListUsers
    user_name = ctx.unique_name("sim2real-user-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    found = None
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for u in page["Users"]:
            if u["UserName"] == user_name:
                found = u
                break
        if found:
            break
    assert found is not None, f"created user {user_name!r} not found in ListUsers"
    assert found["Arn"] == f"arn:aws:iam::{found['Arn'].split(':')[4]}:user/{user_name}", (
        f"unexpected Arn shape for created user: {found['Arn']!r}"
    )

    # --- an explicit Deny actually blocks the real signed call (not merely the simulator) ---
    deny_user = ctx.unique_name("sim2real-list-users-deny-user-")
    iam.create_user(UserName=deny_user, Path="/")
    ctx.on_cleanup(lambda: iam.delete_user(UserName=deny_user))
    deny_user_arn = iam.get_user(UserName=deny_user)["User"]["Arn"]

    iam.put_user_policy(
        UserName=deny_user,
        PolicyName=_ALLOW,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["iam:ListUsers", "iam:ListRoles"], "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=deny_user, PolicyName=_ALLOW))

    key = iam.create_access_key(UserName=deny_user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=deny_user, AccessKeyId=key["AccessKeyId"]))
    as_user = _client_for_credentials(ctx, key["AccessKeyId"], key["SecretAccessKey"])

    # Positive control, captured BEFORE anything is broken: with only the Allow in place,
    # both the action under test and its sibling succeed for the freshly-minted principal.
    before_list = _poll(
        lambda: _error_code(lambda: as_user.list_users()),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the Allow becomes effective for iam:ListUsers on a real signed call",
    )
    assert before_list == "UNEXPECTED_SUCCESS", (
        f"with only the Allow in place the real signed ListUsers must succeed; got {before_list!r}"
    )
    before_roles = _poll(
        lambda: _error_code(lambda: as_user.list_roles()),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the Allow becomes effective for iam:ListRoles on a real signed call",
    )
    assert before_roles == "UNEXPECTED_SUCCESS", (
        f"with only the Allow in place the real signed ListRoles must succeed; got {before_roles!r}"
    )

    # Break exactly ONE thing: a second inline policy denying iam:ListUsers only.
    iam.put_user_policy(
        UserName=deny_user,
        PolicyName=_DENY,
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "iam:ListUsers", "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(lambda: _drop_deny(iam, deny_user))

    denial = {}

    def _probe_denied():
        try:
            as_user.list_users()
        except ClientError as exc:
            denial["message"] = exc.response.get("Error", {}).get("Message")
            return exc.response.get("Error", {}).get("Code")
        return "UNEXPECTED_SUCCESS"

    after_list = _poll(
        _probe_denied,
        lambda c: c == "AccessDenied",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the explicit Deny takes effect on the real signed ListUsers",
    )
    assert after_list == "AccessDenied", (
        f"an explicit Deny naming iam:ListUsers must refuse the real signed call with exactly "
        f"AccessDenied; got {after_list!r}"
    )
    expected_denial = (
        f"User: arn:aws:iam::{ctx.account}:user/{deny_user} is not authorized to perform: "
        f"iam:ListUsers on resource: arn:aws:iam::{ctx.account}:user/ with an explicit deny in an "
        f"identity-based policy"
    )
    assert denial.get("message") == expected_denial, (
        f"the explicit Deny's refusal must carry AWS's exact message {expected_denial!r}; got "
        f"{denial.get('message')!r}"
    )

    # The Deny is SCOPED to the action it names -- an emulator that revokes everything fails here.
    after_roles = _poll(
        lambda: _error_code(lambda: as_user.list_roles()),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the sibling action iam:ListRoles is unaffected by the Deny",
    )
    assert after_roles == "UNEXPECTED_SUCCESS", (
        f"the Deny names iam:ListUsers only, so iam:ListRoles must still succeed for the same "
        f"principal; got {after_roles!r} -- a Deny is not a blanket revoke"
    )

    # The simulator must agree, and must call it an EXPLICIT deny with the deny policy named.
    sim = _poll(
        lambda: _decisions(iam, deny_user_arn, ["iam:ListUsers"]),
        lambda d: d.get("iam:ListUsers", {}).get("EvalDecision") == "explicitDeny",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the simulator reports explicitDeny for iam:ListUsers",
    )
    decision = sim["iam:ListUsers"]
    assert decision["EvalDecision"] == "explicitDeny", (
        f"with a Deny statement present the simulator must say 'explicitDeny', not "
        f"{decision['EvalDecision']!r}"
    )
    sources = {s.get("SourcePolicyId") for s in decision.get("MatchedStatements", [])}
    assert sources == {f"user_{deny_user}_{_DENY}"}, (
        f"the deny must be attributed to the stored inline policy that carries it, and to nothing "
        f"else: expected {{{f'user_{deny_user}_{_DENY}'!r}}}, got {sorted(s for s in sources if s)!r}"
    )

    # --- Reverse the one change: the effect must be reversible, so the middle state was caused by
    #     the Deny and not by drift.
    iam.delete_user_policy(UserName=deny_user, PolicyName=_DENY)
    restored = _poll(
        lambda: _error_code(lambda: as_user.list_users()),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="deleting the Deny restores the real signed ListUsers call",
    )
    assert restored == "UNEXPECTED_SUCCESS", (
        f"deleting the Deny must restore the Allow's grant on the real signed call; got {restored!r}"
    )


def _drop_deny(iam, user):
    """Teardown-only: the body deletes this policy itself, so tolerate it already being gone."""
    try:
        iam.delete_user_policy(UserName=user, PolicyName=_DENY)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _error_code(fn):
    """The captured AWS error code, or a sentinel that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "UNEXPECTED_SUCCESS"


def _client_for_credentials(ctx, access_key_id, secret_access_key, service="iam"):
    """A client signing AS the minted principal, so the Deny is checked on the enforcement path.

    ``ctx.client(..., creds=...)`` keeps this target's endpoint, region and TLS settings.
    """
    return ctx.client(
        service,
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )


def _decisions(iam, source_arn, actions):
    results = iam.simulate_principal_policy(PolicySourceArn=source_arn, ActionNames=actions)[
        "EvaluationResults"
    ]
    return {r["EvalActionName"]: r for r in results}


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s; last observation {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
