"""op-contract-listRoles-missing-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listRoles-missing-permission-denied"
GROUP = "error-semantics"
SERVICES = ["iam"]

_ALLOW = "sim2real-behav-listroles-allow-both"
_DENY = "sim2real-behav-listroles-deny"


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
    """A client signing AS the minted principal, so the Deny is checked on the enforcement path.

    ``ctx.client(..., creds=...)`` keeps this target's endpoint, region and TLS settings.
    """
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


def _drop_deny(iam, user):
    """Teardown-only: the body deletes this policy itself, so tolerate it already being gone."""
    try:
        iam.delete_user_policy(UserName=user, PolicyName=_DENY)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _decisions(iam, source_arn, actions):
    results = iam.simulate_principal_policy(PolicySourceArn=source_arn, ActionNames=actions)[
        "EvaluationResults"
    ]
    return {r["EvalActionName"]: r for r in results}


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An explicit Deny on iam:ListRoles makes a signed ListRoles fail AccessDenied (exact message)
    while ListUsers stays allowed; the simulator attributes it to that policy. After removal,
    ListRoles succeeds and shows a new role with its trust policy."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-listroles-user-")

    iam.create_user(
        UserName=user,
        Path="/",
        Tags=[{"Key": "sim2real", "Value": "op-contract-listRoles-missing-permission-denied"}],
    )
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    iam.put_user_policy(
        UserName=user,
        PolicyName=_ALLOW,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:ListRoles", "iam:ListUsers"],
                "Resource": "*",
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=_ALLOW))

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))
    as_user = _client_for_credentials(ctx, key["AccessKeyId"], key["SecretAccessKey"])

    # IAM propagates the new key and grant eventually, so success is polled with a bound.
    before_roles = _poll(
        lambda: _error_code(lambda: as_user.list_roles(MaxItems=1)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the Allow becomes effective for iam:ListRoles on a real signed call",
    )
    assert before_roles == "UNEXPECTED_SUCCESS", (
        f"the identity policy grants iam:ListRoles, so the real signed call must succeed before "
        f"any Deny is attached; got {before_roles!r}"
    )
    before_users = _poll(
        lambda: _error_code(lambda: as_user.list_users(MaxItems=1)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the Allow becomes effective for iam:ListUsers on a real signed call",
    )
    assert before_users == "UNEXPECTED_SUCCESS", (
        f"the identity policy grants iam:ListUsers, so the real signed call must succeed before "
        f"any Deny is attached; got {before_users!r}"
    )

    iam.put_user_policy(
        UserName=user,
        PolicyName=_DENY,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "iam:ListRoles", "Resource": "*"}],
        }),
    )
    ctx.on_cleanup(lambda: _drop_deny(iam, user))

    denial = {}

    def _probe_denied():
        try:
            as_user.list_roles(MaxItems=1)
        except ClientError as exc:
            denial["message"] = exc.response.get("Error", {}).get("Message")
            return exc.response.get("Error", {}).get("Code")
        return "UNEXPECTED_SUCCESS"

    denied = _poll(
        _probe_denied,
        lambda c: c == "AccessDenied",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the explicit Deny takes effect on the real signed ListRoles",
    )
    assert denied == "AccessDenied", (
        "an explicit Deny naming iam:ListRoles must refuse the real signed call with exactly "
        f"AccessDenied; got {denied!r}"
    )
    expected_denial = (
        f"User: arn:aws:iam::{ctx.account}:user/{user} is not authorized to perform: "
        f"iam:ListRoles on resource: arn:aws:iam::{ctx.account}:role/ with an explicit deny in an "
        f"identity-based policy"
    )
    assert denial.get("message") == expected_denial, (
        f"the explicit Deny's refusal must carry AWS's exact message {expected_denial!r}; got "
        f"{denial.get('message')!r}"
    )

    # The poll only tolerates replica lag; the grant was already proven live above.
    sibling = _poll(
        lambda: _error_code(lambda: as_user.list_users(MaxItems=1)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the sibling action iam:ListUsers is unaffected by the Deny",
    )
    assert sibling == "UNEXPECTED_SUCCESS", (
        "the Deny names iam:ListRoles only, so the identically-granted iam:ListUsers must still "
        f"succeed for the same principal; got {sibling!r} -- a Deny is not a blanket revoke"
    )

    sim = _poll(
        lambda: _decisions(iam, user_arn, ["iam:ListRoles"]),
        lambda d: d.get("iam:ListRoles", {}).get("EvalDecision") == "explicitDeny",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the simulator reports explicitDeny for iam:ListRoles",
    )
    assert sim["iam:ListRoles"]["EvalDecision"] == "explicitDeny", (
        f"with a Deny statement present the simulator must say 'explicitDeny'; got "
        f"{sim['iam:ListRoles']['EvalDecision']!r}"
    )
    matched = sim["iam:ListRoles"].get("MatchedStatements", [])
    sources = {s.get("SourcePolicyId") for s in matched}
    assert sources == {f"user_{user}_{_DENY}"}, (
        f"the deny must be attributed to the stored inline policy that carries it, and to nothing "
        f"else: expected {{{f'user_{user}_{_DENY}'!r}}}, got {sorted(s for s in sources if s)!r}"
    )

    iam.delete_user_policy(UserName=user, PolicyName=_DENY)
    restored = _poll(
        lambda: _error_code(lambda: as_user.list_roles(MaxItems=1)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="deleting the Deny restores the real signed ListRoles",
    )
    assert restored == "UNEXPECTED_SUCCESS", (
        f"deleting the Deny must restore the Allow's grant on the real signed call; got {restored!r}"
    )

    role = ctx.unique_name("sim2real-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    })
    iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": "op-contract-listRoles-missing-permission-denied"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))

    found = None
    paginator = as_user.get_paginator("list_roles")
    for page in paginator.paginate():
        for r in page["Roles"]:
            if r["RoleName"] == role:
                found = r
                break
        if found:
            break
    assert found is not None, "created role not found in the same principal's real ListRoles"
    assert found["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["Service"] == "ec2.amazonaws.com", (
        f"the trust policy must survive the round trip through ListRoles; got "
        f"{found['AssumeRolePolicyDocument']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
