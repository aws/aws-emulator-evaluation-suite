"""permissions-boundary-caps-a-real-signed-call."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "permissions-boundary-caps-a-real-signed-call"
GROUP = 'permissions_boundaries'
SERVICES = ['iam']

_PROPAGATION = frozenset({"InvalidClientTokenId", "SignatureDoesNotMatch"})
_IDENTITY = "sim2real-behav-bound-identity"


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _outcome(fn):
    """(code, message) of the captured AWS error, or ("UNEXPECTED_SUCCESS", None) -- a sentinel
    that cannot be mistaken for an error code -- on success."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    return "UNEXPECTED_SUCCESS", None


def _error_code(fn):
    """The captured AWS error code, or the "UNEXPECTED_SUCCESS" sentinel on success."""
    return _outcome(fn)[0]


def _client_for_credentials(ctx, access_key_id, secret_access_key, service="iam"):
    """A client signing AS the minted principal, built by ``ctx.client`` so it keeps this
    target's endpoint, region and TLS settings."""
    return ctx.client(
        service,
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )


def _with_authorization_details(base, message):
    """IAM's enhanced access-denied text: ``base`` followed by a pointer to a per-request
    authorization id. The id is an opaque token the service mints for this one refusal, so it is
    the only part read back from the message; everything else is built from known values. The
    console link names us-east-1 because IAM's global endpoint signs every request there."""
    region = "us-east-1"
    marker = "authorization id: "
    auth_id = message.rsplit(marker, 1)[-1] if message and marker in message else "<absent>"
    return (
        f"{base}. Go to https://{region}.console.aws.amazon.com/iam/home?region={region}"
        f"#/authorization-details/{auth_id} for complete details, or call the "
        f"GetRequestAuthorizationDetails API with the following authorization id: {auth_id}"
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


def _drop_boundary(iam, user):
    """Teardown-only: the body detaches the boundary itself, so tolerate it already being gone."""
    try:
        iam.delete_user_permissions_boundary(UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _boundary_details(iam, source_arn, actions, resource_arns):
    """{action: AllowedByPermissionsBoundary or None} -- the simulator's STATED reason."""
    results = iam.simulate_principal_policy(
        PolicySourceArn=source_arn, ActionNames=actions, ResourceArns=resource_arns
    )["EvaluationResults"]
    return {
        r["EvalActionName"]: r.get("PermissionsBoundaryDecisionDetail", {}).get(
            "AllowedByPermissionsBoundary"
        )
        for r in results
    }


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c7")
def run(ctx) -> None:
    """A permissions boundary intersects the identity policy on real signed calls: an action the
    identity policy allows but the boundary omits fails with AccessDenied and the exact message
    while an action both allow succeeds, and detaching the boundary restores the capped action."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-bound-user-")

    iam.create_user(UserName=user, Path="/")
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    iam.put_user_policy(
        UserName=user,
        PolicyName=_IDENTITY,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:GetUser", "iam:ListAccessKeys"],
                "Resource": user_arn,
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=_IDENTITY))

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"])
    )
    as_user = _client_for_credentials(ctx, key["AccessKeyId"], key["SecretAccessKey"])

    # --- Control #1, before the boundary exists: the identity policy alone grants both. IAM
    #     replicates the key AND the grant per-replica and reports neither as effective, so every
    #     leg expecting a fresh grant to work is a bounded poll on that success and raises on
    #     non-convergence.
    before_get = _poll(
        lambda: _error_code(lambda: as_user.get_user(UserName=user)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the identity policy becomes effective for iam:GetUser on a real signed call",
    )
    assert before_get == "UNEXPECTED_SUCCESS", (
        f"the identity policy grants iam:GetUser, so the real signed call must succeed before any "
        f"boundary is attached; got {before_get!r}"
    )
    before_list = _poll(
        lambda: _error_code(lambda: as_user.list_access_keys(UserName=user)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the identity policy becomes effective for iam:ListAccessKeys",
    )
    assert before_list == "UNEXPECTED_SUCCESS", (
        f"the identity policy grants iam:ListAccessKeys, so the real signed call must succeed "
        f"before any boundary is attached; got {before_list!r}"
    )

    # --- Break exactly one thing: a boundary that allows iam:GetUser and nothing else.
    boundary_arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-bound-pol-"),
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:GetUser", "Resource": "*"}],
        }),
        Description="sim2real permissions-boundary intersection check",
        Tags=[{"Key": "sim2real", "Value": "permissions-boundary-caps-a-real-signed-call"}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=boundary_arn))

    iam.put_user_permissions_boundary(UserName=user, PermissionsBoundary=boundary_arn)
    ctx.on_cleanup(lambda: _drop_boundary(iam, user))
    stored = iam.get_user(UserName=user)["User"].get("PermissionsBoundary", {})
    assert stored.get("PermissionsBoundaryArn") == boundary_arn, (
        f"the boundary must be observably attached before anything is concluded from its effect: "
        f"expected {boundary_arn!r}, GetUser reported {stored!r}"
    )

    capped, capped_message = _poll(
        lambda: _outcome(lambda: as_user.list_access_keys(UserName=user)),
        lambda o: o[0] == "AccessDenied",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the boundary caps iam:ListAccessKeys on the real signed call",
    )
    assert capped == "AccessDenied", (
        "iam:ListAccessKeys is allowed by the identity policy but absent from the boundary, so the "
        f"real signed call must be refused with exactly AccessDenied; got {capped!r}"
    )
    expected = _with_authorization_details(
        f"User: {user_arn} is not authorized to perform: iam:ListAccessKeys on resource: user "
        f"{user} because no permissions boundary allows the iam:ListAccessKeys action",
        capped_message,
    )
    assert capped_message == expected, f"expected message {expected!r}, got {capped_message!r}"

    # --- Control #2, at the same moment: the boundary NARROWS, it does not revoke. Bounded poll
    #     rather than a single shot, for the same replica-lag reason; it still raises if the
    #     in-boundary action never recovers, which is the fidelity failure this leg exists to catch.
    inside = _poll(
        lambda: _error_code(lambda: as_user.get_user(UserName=user)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the in-boundary action iam:GetUser stays permitted under the boundary",
    )
    assert inside == "UNEXPECTED_SUCCESS", (
        "iam:GetUser is allowed by BOTH documents, so it must still succeed while the boundary is "
        f"attached; got {inside!r} -- an emulator that treats a boundary as a revoke fails here"
    )

    # --- The simulator's STATED reason must match its own behaviour.
    detail = _poll(
        lambda: _boundary_details(
            iam, user_arn, ["iam:GetUser", "iam:ListAccessKeys"], [user_arn]
        ),
        lambda d: d.get("iam:ListAccessKeys") is False,
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the simulator reports AllowedByPermissionsBoundary=false for ListAccessKeys",
    )
    assert detail["iam:ListAccessKeys"] is False, (
        "the capped action's denial must be ATTRIBUTED to the boundary via "
        f"AllowedByPermissionsBoundary=false; got {detail['iam:ListAccessKeys']!r}"
    )
    assert detail["iam:GetUser"] is True, (
        "the in-boundary action must report AllowedByPermissionsBoundary=true, so the stated reason "
        f"agrees with the real outcome for both actions; got {detail['iam:GetUser']!r}"
    )

    # --- Control #3: detaching restores the capped action, so the cap was the boundary's doing.
    iam.delete_user_permissions_boundary(UserName=user)
    assert "PermissionsBoundary" not in iam.get_user(UserName=user)["User"], (
        "the boundary must be gone from GetUser after DeleteUserPermissionsBoundary"
    )
    restored = _poll(
        lambda: _error_code(lambda: as_user.list_access_keys(UserName=user)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="detaching the boundary restores iam:ListAccessKeys",
    )
    assert restored == "UNEXPECTED_SUCCESS", (
        f"detaching the boundary must restore the identity policy's full grant on the real signed "
        f"call; got {restored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
