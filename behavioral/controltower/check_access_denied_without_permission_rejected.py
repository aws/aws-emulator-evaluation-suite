"""access-denied-without-permission-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "access-denied-without-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["controltower"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An explicit Deny on controltower:ListLandingZones over a role's Allow makes the call fail with the
    exact AccessDeniedException while the caller's own call succeeds; removing the Deny restores the
    role's call, so the Deny caused the refusal."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-ct-deny-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "controltower:ListLandingZones",
            "Resource": "*",
        }],
    }
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": "controltower:ListLandingZones",
            "Resource": "*",
        }],
    }

    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="allow-list-landing-zones", PolicyDocument=json.dumps(allow_policy)
    )
    ctx.on_cleanup(lambda: _drop_policy(iam, role_name, "allow-list-landing-zones"))

    # positive control on the SAME principal, before any Deny exists
    before = _poll(
        lambda: _probe(ctx, role_arn),
        lambda c: c[0] == _SUCCEEDED,
        timeout_s=60.0,
        interval_s=2.0,
        description="the explicit Allow becomes effective for controltower:ListLandingZones",
    )
    assert before[0] == _SUCCEEDED, (
        f"the role's explicit Allow grants controltower:ListLandingZones, so the real signed call "
        f"must succeed before any Deny is attached; got {before!r}"
    )

    # break exactly one thing: an explicit Deny layered on top of the Allow
    iam.put_role_policy(
        RoleName=role_name, PolicyName="deny-list-landing-zones", PolicyDocument=json.dumps(deny_policy)
    )
    ctx.on_cleanup(lambda: _drop_policy(iam, role_name, "deny-list-landing-zones"))

    code, message = _poll(
        lambda: _probe(ctx, role_arn),
        lambda c: c[0] == "AccessDeniedException",
        timeout_s=60.0,
        interval_s=2.0,
        description="the explicit Deny takes effect for controltower:ListLandingZones",
    )
    assert code == "AccessDeniedException", (
        f"the explicit Deny must override the Allow with exactly AccessDeniedException; got {code!r}"
    )
    assert message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-ct-denied-probe "
        f"is not authorized to perform: controltower:ListLandingZones on resource: "
        f"arn:aws:controltower:{ctx.region}:{account_id}:landingzone/* "
        f"with an explicit deny in an identity-based policy"
    ), message

    # positive control: a different, normally-privileged caller in the same account still succeeds
    ct = ctx.client("controltower")
    ok = ct.list_landing_zones()
    assert "landingZones" in ok, (
        f"expected the privileged caller's ListLandingZones response to include landingZones; "
        f"got keys {sorted(ok)}"
    )

    # restore: remove the explicit Deny, leaving only the original Allow
    iam.delete_role_policy(RoleName=role_name, PolicyName="deny-list-landing-zones")

    restored = _poll(
        lambda: _probe(ctx, role_arn),
        lambda c: c[0] == _SUCCEEDED,
        timeout_s=60.0,
        interval_s=2.0,
        description="removing the explicit Deny restores controltower:ListLandingZones for the same role",
    )
    assert restored[0] == _SUCCEEDED, (
        f"removing the Deny must restore the identical call for the SAME role, proving the Deny "
        f"(not an absent grant) caused the earlier rejection; got {restored!r}"
    )


def _drop_policy(iam, role_name, policy_name):
    from botocore.exceptions import ClientError

    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


# No AWS error code can equal this, so a success never passes for a refusal.
_SUCCEEDED = "<call succeeded>"


def _outcome(fn) -> tuple[str, str]:
    """(error code, message) for a refused call; (_SUCCEEDED, "") when it succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    return _SUCCEEDED, ""


def _probe(ctx, role_arn: str) -> tuple[str, str]:
    """ListLandingZones as the assumed role: its (code, message), or (_SUCCEEDED, "").
    Assumes the role fresh each call: IAM role/policy propagation can lag by a few seconds."""
    sts = ctx.client("sts")
    try:
        creds = sts.assume_role(
            RoleArn=role_arn, RoleSessionName="sim2real-ct-denied-probe"
        )["Credentials"]
    except Exception:
        return "ASSUME_ROLE_PENDING", ""
    client = ctx.client(
        "controltower",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return _outcome(lambda: client.list_landing_zones())


def _poll(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
