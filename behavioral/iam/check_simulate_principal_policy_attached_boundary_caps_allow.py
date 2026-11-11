"""simulate-principal-policy-attached-boundary-caps-allow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "simulate-principal-policy-attached-boundary-caps-allow"
GROUP = 'permissions_boundaries'
SERVICES = ['iam']

IDENTITY_ALLOW_ALL_S3 = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
    }
)
BOUNDARY_READ_ONLY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "*"}
        ],
    }
)


def _poll(fn, pred, *, timeout_s, interval_s):
    """Poll fn() until pred(value) or the deadline; return the last value either way."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _drop_boundary(iam, user):
    """Teardown-only: the body removes the boundary itself, so tolerate it already being gone."""
    try:
        iam.delete_user_permissions_boundary(UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _decisions(iam, user_arn, actions):
    results = iam.simulate_principal_policy(PolicySourceArn=user_arn, ActionNames=actions)[
        "EvaluationResults"
    ]
    return {r["EvalActionName"]: r for r in results}


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SimulatePrincipalPolicy honours the boundary stored on the user: PutUserPermissionsBoundary
    flips an identity-allowed action outside the boundary to implicitDeny, and
    DeleteUserPermissionsBoundary restores the allow.
    """
    iam = ctx.client("iam")
    actions = ["s3:GetObject", "s3:DeleteObject"]

    user = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(
        UserName=user, Path="/", Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    identity_arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-ident-"),
        PolicyDocument=IDENTITY_ALLOW_ALL_S3,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=identity_arn))
    boundary_arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-bound-"),
        PolicyDocument=BOUNDARY_READ_ONLY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=boundary_arn))

    iam.attach_user_policy(UserName=user, PolicyArn=identity_arn)
    ctx.on_cleanup(lambda: iam.detach_user_policy(UserName=user, PolicyArn=identity_arn))

    # --- Baseline: attachment is eventually consistent for the simulator, so poll for the allow.
    baseline = _poll(
        lambda: _decisions(iam, user_arn, actions),
        lambda d: d.get("s3:DeleteObject", {}).get("EvalDecision") == "allowed",
        timeout_s=60,
        interval_s=3,
    )
    assert baseline["s3:GetObject"]["EvalDecision"] == "allowed", (
        f"attached s3:* must allow s3:GetObject; got {baseline['s3:GetObject']['EvalDecision']!r}"
    )
    assert baseline["s3:DeleteObject"]["EvalDecision"] == "allowed", (
        "with no boundary set, attached s3:* must allow s3:DeleteObject; got "
        f"{baseline['s3:DeleteObject']['EvalDecision']!r}"
    )

    # --- Set the read-only boundary on the user.
    iam.put_user_permissions_boundary(UserName=user, PermissionsBoundary=boundary_arn)
    ctx.on_cleanup(lambda: _drop_boundary(iam, user))
    stored = iam.get_user(UserName=user)["User"].get("PermissionsBoundary", {})
    assert stored.get("PermissionsBoundaryArn") == boundary_arn, (
        f"boundary must be stored on the user before simulating; got {stored!r}"
    )

    capped = _poll(
        lambda: _decisions(iam, user_arn, actions),
        lambda d: d.get("s3:DeleteObject", {}).get("EvalDecision") == "implicitDeny",
        timeout_s=60,
        interval_s=3,
    )
    assert capped["s3:DeleteObject"]["EvalDecision"] == "implicitDeny", (
        "the stored read-only boundary must cap the attached s3:* allow for s3:DeleteObject; "
        f"expected 'implicitDeny', got {capped['s3:DeleteObject']['EvalDecision']!r}"
    )
    capped_detail = capped["s3:DeleteObject"].get("PermissionsBoundaryDecisionDetail", {})
    assert capped_detail.get("AllowedByPermissionsBoundary", False) is False, (
        "the blocked action must report AllowedByPermissionsBoundary=false; got "
        f"{capped_detail!r}"
    )
    assert capped["s3:GetObject"]["EvalDecision"] == "allowed", (
        "s3:GetObject is inside the boundary and must stay allowed -- the boundary narrows, it does "
        f"not revoke everything; got {capped['s3:GetObject']['EvalDecision']!r}"
    )

    # --- Restore: removing the boundary restores the identity policy's full grant.
    iam.delete_user_permissions_boundary(UserName=user)
    assert "PermissionsBoundary" not in iam.get_user(UserName=user)["User"], (
        "boundary must be gone from GetUser after DeleteUserPermissionsBoundary"
    )
    restored = _poll(
        lambda: _decisions(iam, user_arn, actions),
        lambda d: d.get("s3:DeleteObject", {}).get("EvalDecision") == "allowed",
        timeout_s=60,
        interval_s=3,
    )
    assert restored["s3:DeleteObject"]["EvalDecision"] == "allowed", (
        "removing the boundary must restore the s3:DeleteObject allow; got "
        f"{restored['s3:DeleteObject']['EvalDecision']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
