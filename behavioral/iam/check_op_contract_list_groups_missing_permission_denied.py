"""op-contract-listGroups-missing-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listGroups-missing-permission-denied"
GROUP = "error-semantics"
SERVICES = ["iam"]

_ALLOW = "sim2real-behav-lg-allow-both"
_DENY = "sim2real-behav-lg-deny-listgroups"


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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s; last observation {last!r}")
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


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A signed ListGroups succeeds under an Allow, fails AccessDenied with AWS's exact message once
    an explicit Deny names it, and succeeds again after the Deny is removed; ListRoles stays
    allowed and SimulatePrincipalPolicy reports explicitDeny."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-lg-user-")

    iam.create_user(UserName=user, Path="/", Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))

    iam.put_user_policy(
        UserName=user,
        PolicyName=_ALLOW,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["iam:ListGroups", "iam:ListRoles"], "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=_ALLOW))

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))
    as_user = _client_for_credentials(ctx, key["AccessKeyId"], key["SecretAccessKey"])

    # IAM propagates the new key and grant eventually, so success is polled with a bound.
    before = _poll(
        lambda: _error_code(lambda: as_user.list_groups(MaxItems=5)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the Allow becomes effective for iam:ListGroups on a real signed call",
    )
    assert before == "UNEXPECTED_SUCCESS", (
        f"with only the Allow in place the real signed ListGroups must succeed; got {before!r} -- "
        f"the control failed, so nothing below would be interpretable"
    )
    before_sibling = _poll(
        lambda: _error_code(lambda: as_user.list_roles(MaxItems=5)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the Allow becomes effective for iam:ListRoles on a real signed call",
    )
    assert before_sibling == "UNEXPECTED_SUCCESS", (
        f"with only the Allow in place the real signed ListRoles must succeed; got {before_sibling!r}"
    )

    iam.put_user_policy(
        UserName=user,
        PolicyName=_DENY,
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "iam:ListGroups", "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(lambda: _drop_deny(iam, user))

    denial = {}

    def _probe_denied():
        try:
            as_user.list_groups(MaxItems=5)
        except ClientError as exc:
            denial["message"] = exc.response.get("Error", {}).get("Message")
            return exc.response.get("Error", {}).get("Code")
        return "UNEXPECTED_SUCCESS"

    denied = _poll(
        _probe_denied,
        lambda c: c == "AccessDenied",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the explicit Deny takes effect on the real signed ListGroups",
    )
    assert denied == "AccessDenied", (
        f"an explicit Deny naming iam:ListGroups must refuse the real signed call with exactly "
        f"AccessDenied; got {denied!r}"
    )
    expected_denial = (
        f"User: arn:aws:iam::{ctx.account}:user/{user} is not authorized to perform: "
        f"iam:ListGroups on resource: arn:aws:iam::{ctx.account}:group/ with an explicit deny in an "
        f"identity-based policy"
    )
    assert denial.get("message") == expected_denial, (
        f"the explicit Deny's refusal must carry AWS's exact message {expected_denial!r}; got "
        f"{denial.get('message')!r}"
    )

    after_sibling = _poll(
        lambda: _error_code(lambda: as_user.list_roles(MaxItems=5)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the sibling action iam:ListRoles is unaffected by the Deny",
    )
    assert after_sibling == "UNEXPECTED_SUCCESS", (
        f"the Deny names iam:ListGroups only, so iam:ListRoles must still succeed for the same "
        f"principal; got {after_sibling!r} -- a Deny is not a blanket revoke"
    )

    user_arn = iam.get_user(UserName=user)["User"]["Arn"]
    sim_eval = _poll(
        lambda: iam.simulate_principal_policy(PolicySourceArn=user_arn, ActionNames=["iam:ListGroups"])[
            "EvaluationResults"
        ][0],
        lambda r: r["EvalDecision"] == "explicitDeny",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the simulator reports explicitDeny for iam:ListGroups",
    )
    assert sim_eval["EvalDecision"] == "explicitDeny", (
        f"with a Deny statement present the simulator must say 'explicitDeny'; got "
        f"{sim_eval['EvalDecision']!r}"
    )

    iam.delete_user_policy(UserName=user, PolicyName=_DENY)
    # Keep the response of the polled call itself: a later call can hit a replica that still
    # has the Deny.
    _restored_resp = {}

    def _probe_restored():
        try:
            _restored_resp["value"] = as_user.list_groups(MaxItems=5)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        return "UNEXPECTED_SUCCESS"

    restored = _poll(
        _probe_restored,
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="deleting the Deny restores the real signed ListGroups",
    )
    assert restored == "UNEXPECTED_SUCCESS", (
        f"deleting the Deny must restore the Allow's grant on the real signed call; got {restored!r}"
    )

    resp = _restored_resp["value"]
    assert isinstance(resp["IsTruncated"], bool)
    for g in resp["Groups"]:
        assert g["GroupName"] and g["Arn"].startswith("arn:aws:iam::")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
