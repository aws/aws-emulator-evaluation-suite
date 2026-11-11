"""op-contract-listInstanceProfiles-missing-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listInstanceProfiles-missing-permission-denied"
GROUP = "error-semantics"
SERVICES = ["iam"]

_ALLOW = "sim2real-behav-lip-allow"
_DENY = "sim2real-behav-lip-deny"


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A real signed ListInstanceProfiles call succeeds under an Allow, fails with
    AccessDenied and the exact message once an explicit Deny is added (the simulator reports
    explicitDeny from that user policy), and succeeds again once the Deny is removed."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-lip-user-")

    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))

    iam.put_user_policy(
        UserName=user,
        PolicyName=_ALLOW,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "iam:ListInstanceProfiles", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=_ALLOW))

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))
    as_user = _client_for_credentials(ctx, key["AccessKeyId"], key["SecretAccessKey"])

    # --- Positive control, captured BEFORE anything is broken.
    before = _poll(
        lambda: _call(lambda: as_user.list_instance_profiles()),
        lambda r: r[0] == "ok",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the Allow becomes effective for a real signed ListInstanceProfiles call",
    )
    assert before[0] == "ok", (
        f"with only the Allow in place the real signed call must succeed; got {before!r} -- the "
        "control failed, so nothing below would be interpretable"
    )

    # --- Break exactly ONE thing: an inline policy that denies iam:ListInstanceProfiles and
    #     nothing else.
    iam.put_user_policy(
        UserName=user,
        PolicyName=_DENY,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Deny", "Action": "iam:ListInstanceProfiles", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: _drop_deny(iam, user))

    denied = _poll(
        lambda: _call(lambda: as_user.list_instance_profiles()),
        lambda r: r[:2] == ("error", "AccessDenied"),
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the explicit Deny takes effect on the real signed call",
    )
    assert denied[:2] == ("error", "AccessDenied"), (
        "an explicit Deny naming iam:ListInstanceProfiles must refuse the real signed call with "
        f"exactly AccessDenied; got {denied!r}"
    )
    expected_denial = (
        f"User: arn:aws:iam::{ctx.account}:user/{user} is not authorized to perform: "
        f"iam:ListInstanceProfiles on resource: arn:aws:iam::{ctx.account}:instance-profile/ with "
        f"an explicit deny in an identity-based policy"
    )
    assert denied[2] == expected_denial, (
        f"the explicit Deny's refusal must carry AWS's exact message {expected_denial!r}; got "
        f"{denied[2]!r}"
    )

    # The simulator must independently agree, and attribute the block to the stored deny policy.
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]
    sim = iam.simulate_principal_policy(
        PolicySourceArn=user_arn, ActionNames=["iam:ListInstanceProfiles"]
    )["EvaluationResults"][0]
    assert sim["EvalDecision"] == "explicitDeny", sim
    sources = {s.get("SourcePolicyId") for s in sim.get("MatchedStatements", [])}
    assert sources == {f"user_{user}_{_DENY}"}, (
        f"the deny must be attributed to the stored inline policy that carries it; got {sources!r}"
    )

    # --- Reverse the one change: the effect must be reversible, so the middle state was caused by
    #     the Deny and not by drift.
    iam.delete_user_policy(UserName=user, PolicyName=_DENY)
    restored = _poll(
        lambda: _call(lambda: as_user.list_instance_profiles()),
        lambda r: r[0] == "ok",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="deleting the Deny restores the real signed call",
    )
    assert restored[0] == "ok", (
        f"deleting the Deny must restore the Allow's grant on the real signed call; got {restored!r}"
    )

    # Terminal independent read: the SAME successfully-polled response is a genuine
    # ListInstanceProfiles body, not a stub that merely stopped raising. Reading this shape via a
    # fresh, unprotected call would be vulnerable to IAM's own per-replica lag -- the same hazard
    # that requires every transition above to be a bounded poll rather than a single shot.
    final = restored[1]
    assert isinstance(final.get("InstanceProfiles"), list)
    assert isinstance(final.get("IsTruncated"), bool)


def _call(fn):
    """("ok", response) on success, or ("error", code, message) on a ClientError."""
    try:
        return ("ok", fn())
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return ("error", err.get("Code"), err.get("Message"))


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
