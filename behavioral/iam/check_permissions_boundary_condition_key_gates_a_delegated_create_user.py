"""permissions-boundary-condition-key-gates-a-delegated-create-user."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "permissions-boundary-condition-key-gates-a-delegated-create-user"
GROUP = "permissions_boundaries"
SERVICES = ["iam"]

_DELEGATION = "sim2real-behav-boundary-gated-delegation"
_MARK = [{"Key": "sim2real", "Value": CHECK}]


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A delegated CreateUser conditioned on iam:PermissionsBoundary succeeds only with the required
    boundary: omitting it or naming a decoy fails with AccessDenied and the exact message, the same
    call with the required boundary then succeeds, and the policies report usage counts of 2 and 0."""
    iam = ctx.client("iam")

    required_arn = _boundary_policy(ctx, iam, "sim2real-pbcond-required-", "iam:GetUser")
    decoy_arn = _boundary_policy(ctx, iam, "sim2real-pbcond-decoy-", "iam:ListAccessKeys")
    assert required_arn != decoy_arn, (
        f"the two boundary policies must be distinct for the condition to discriminate; both "
        f"resolved to {required_arn!r}"
    )

    admin = ctx.unique_name("sim2real-pbcond-admin-")
    iam.create_user(UserName=admin, Path="/", Tags=_MARK)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=admin))
    admin_arn = iam.get_user(UserName=admin)["User"]["Arn"]
    account = admin_arn.split(":")[4]

    # Every user this delegated admin may create lives under one generated path, so the grant names
    # no resource the check does not create, and the blast radius is this run's own prefix.
    scope_path = f"/{ctx.unique_name('sim2real-pbcond-')}/"
    creatable = f"arn:aws:iam::{account}:user{scope_path}*"

    iam.put_user_policy(
        UserName=admin,
        PolicyName=_DELEGATION,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                # Unconditioned: gives a credential/grant-propagation control that does not depend
                # on the claim under test.
                {
                    "Sid": "ReadSelf",
                    "Effect": "Allow",
                    "Action": "iam:GetUser",
                    "Resource": admin_arn,
                },
                {
                    "Sid": "CreateOnlyWithRequiredBoundary",
                    "Effect": "Allow",
                    "Action": "iam:CreateUser",
                    "Resource": creatable,
                    "Condition": {"StringEquals": {"iam:PermissionsBoundary": required_arn}},
                },
                # Tags=_MARK on the CreateUser calls below makes iam:TagUser (and, per AWS's own
                # policy-authoring convention, iam:ListUserTags alongside it) a DEPENDENT action on
                # the same request (simulate_principal_policy agrees): granting only
                # iam:CreateUser leaves iam:TagUser implicitDeny and every call below AccessDenied
                # regardless of the boundary, which would misattribute the refusal to the condition
                # under test. Unlike iam:CreateUser, iam:TagUser/iam:ListUserTags do NOT support
                # resource-level scoping to a user ARN pattern -- the identical Resource=creatable
                # pattern that matches for CreateUser left both implicitDeny; only Resource="*"
                # made them match. Unconditioned, like ReadSelf: this is dependency plumbing the
                # request needs to go through at all, not the security property under test, which
                # remains gated solely by CreateOnlyWithRequiredBoundary's Condition.
                {
                    "Sid": "TagOnCreate",
                    "Effect": "Allow",
                    "Action": ["iam:TagUser", "iam:ListUserTags"],
                    "Resource": "*",
                },
            ],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=admin, PolicyName=_DELEGATION))

    key = iam.create_access_key(UserName=admin)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=admin, AccessKeyId=key["AccessKeyId"]))
    as_admin = _signing_as(ctx, "iam", key)

    ready = _poll(
        lambda: _outcome(lambda: as_admin.get_user(UserName=admin)),
        lambda o: o == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the unconditioned iam:GetUser grant becomes effective for the minted key",
    )
    assert ready == "OK", (
        f"the delegated admin's unconditioned grant must work before any CreateUser refusal is "
        f"attributed to the boundary condition; expected 'OK', got {ready!r}"
    )

    compliant = ctx.unique_name("sim2real-pbcond-ok-")
    omitted = ctx.unique_name("sim2real-pbcond-omit-")
    wrong = ctx.unique_name("sim2real-pbcond-wrong-")
    for name in (compliant, omitted, wrong):
        ctx.on_cleanup(lambda n=name: _drop_user(iam, n))

    # --- Positive control: the request that satisfies the Condition.
    made = _poll(
        lambda: _outcome(lambda: as_admin.create_user(
            UserName=compliant, Path=scope_path, PermissionsBoundary=required_arn, Tags=_MARK,
        )),
        lambda o: o in ("OK", "EntityAlreadyExists"),
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the conditioned iam:CreateUser grant takes effect for the required boundary",
    )
    assert made in ("OK", "EntityAlreadyExists"), (
        f"the request attaches exactly the boundary the Condition names, so the real signed "
        f"CreateUser must succeed; expected 'OK', got {made!r}"
    )
    # An independent read, through a different operation, at the destination.
    stored = iam.get_user(UserName=compliant)["User"]
    assert stored.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn") == required_arn, (
        f"the created user must carry the required boundary as read back by GetUser: expected "
        f"{required_arn!r}, got {stored.get('PermissionsBoundary')!r}"
    )

    # --- Break exactly one thing (A): the boundary parameter is OMITTED. Nothing else changes.
    no_boundary, no_boundary_message = _rejected(
        lambda: as_admin.create_user(UserName=omitted, Path=scope_path, Tags=_MARK)
    )
    assert no_boundary == "AccessDenied", (
        f"CreateUser without a PermissionsBoundary fails the StringEquals Condition, so the real "
        f"signed call must be refused with exactly AccessDenied; got {no_boundary!r} -- an emulator "
        f"that never exposes the parameter as a condition key creates an UNBOUNDED user here"
    )
    expected = _create_user_denial(admin_arn, account, scope_path, omitted)
    assert no_boundary_message == expected, (
        f"expected message {expected!r}, got {no_boundary_message!r}"
    )
    _assert_absent(iam, omitted, "the boundary-less CreateUser was refused")

    # --- Break exactly one thing (B): a DIFFERENT, real, attachable boundary. This separates
    #     "the condition is evaluated" from "the parameter is merely required to be present".
    wrong_boundary, wrong_boundary_message = _rejected(
        lambda: as_admin.create_user(
            UserName=wrong, Path=scope_path, PermissionsBoundary=decoy_arn, Tags=_MARK,
        )
    )
    assert wrong_boundary == "AccessDenied", (
        f"the decoy boundary {decoy_arn!r} is a valid attachable policy but is not the ARN the "
        f"Condition names, so the call must be refused with exactly AccessDenied; got "
        f"{wrong_boundary!r} -- an emulator that only checks the parameter is PRESENT passes the "
        f"omitted case and fails here"
    )
    expected = _create_user_denial(admin_arn, account, scope_path, wrong)
    assert wrong_boundary_message == expected, (
        f"expected message {expected!r}, got {wrong_boundary_message!r}"
    )
    _assert_absent(iam, wrong, "the wrong-boundary CreateUser was refused")

    # --- Restore: the SAME user name that was just refused, with the one field corrected.
    repaired = _poll(
        lambda: _outcome(lambda: as_admin.create_user(
            UserName=omitted, Path=scope_path, PermissionsBoundary=required_arn, Tags=_MARK,
        )),
        lambda o: o in ("OK", "EntityAlreadyExists"),
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the refused user name is creatable once the required boundary is supplied",
    )
    assert repaired in ("OK", "EntityAlreadyExists"), (
        f"the identical CreateUser differing only by the corrected PermissionsBoundary must now "
        f"succeed, proving the refusals were the Condition's doing and not a blanket CreateUser "
        f"denial; expected 'OK', got {repaired!r}"
    )
    repaired_view = iam.get_user(UserName=omitted)["User"]
    assert (
        repaired_view.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn") == required_arn
    ), (
        f"the repaired user must carry the required boundary: expected {required_arn!r}, GetUser "
        f"reported {repaired_view.get('PermissionsBoundary')!r}"
    )

    # --- Server-side accounting agrees, and the expected numbers are DERIVED from what this check
    #     did rather than pinned: both policies were created by this run, so nothing else can be
    #     using them as a boundary. Two users ended up bounded by the required policy (the
    #     compliant one and the repaired one) and zero by the decoy.
    decoy_uses = iam.get_policy(PolicyArn=decoy_arn)["Policy"]["PermissionsBoundaryUsageCount"]
    assert decoy_uses == 0, (
        f"the two refused CreateUser calls must have left no trace, so the decoy policy's "
        f"PermissionsBoundaryUsageCount must be exactly 0; got {decoy_uses!r}"
    )
    required_uses = iam.get_policy(PolicyArn=required_arn)["Policy"][
        "PermissionsBoundaryUsageCount"
    ]
    assert required_uses == 2, (
        f"exactly the two users this check successfully created are bounded by the required policy, "
        f"so its PermissionsBoundaryUsageCount must be exactly 2; got {required_uses!r}"
    )


def _outcome(fn):
    """``"OK"`` on success, else the AWS error code.

    ``"OK"`` is a truthy sentinel no AWS error code can equal, and every caller either feeds it to
    ``_poll`` (which RAISES on timeout, so a target that never converges cannot pass) or asserts it
    against an exact expected value. Refusals asserted WITHOUT a preceding poll go through
    ``_rejected``, which raises on an unexpected success.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"
    return "OK"


def _rejected(fn):
    """(code, message) of a call real AWS MUST refuse; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code") or "NO_ERROR_CODE", error.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _create_user_denial(caller_arn, account, path, user):
    """IAM's exact implicit-deny message for a CreateUser the caller's policy does not allow."""
    return (
        f"User: {caller_arn} is not authorized to perform: iam:CreateUser on resource: "
        f"arn:aws:iam::{account}:user{path}{user} because no identity-based policy allows the "
        f"iam:CreateUser action"
    )


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry with a deadline. RAISES on timeout -- never returns its last value on failure.

    IAM replicates a fresh access key and a fresh inline policy per-replica and reports neither as
    effective, so a grant becoming usable is genuinely asynchronous; a wait that gives up is the
    only honest way to express it.
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


def _boundary_policy(ctx, iam, prefix, action):
    """A real, attachable managed policy usable as a permissions boundary. Created, not assumed."""
    arn = iam.create_policy(
        PolicyName=ctx.unique_name(prefix),
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": action, "Resource": "*"}],
        }),
        Description=f"sim2real {CHECK}",
        Tags=_MARK,
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=arn))
    return arn


def _assert_absent(iam, user, why):
    """Effect-absent, two ways: the refused user is neither gettable nor listable."""
    code, message = _rejected(lambda: iam.get_user(UserName=user))
    assert code == "NoSuchEntity", (
        f"{why}, so GetUser on {user!r} must report exactly NoSuchEntity; got {code!r}"
    )
    expected = f"The user with name {user} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    listed = []
    for page in iam.get_paginator("list_users").paginate():
        listed.extend(u["UserName"] for u in page["Users"])
    assert user not in listed, (
        f"{why}, so {user!r} must not appear in the paginated ListUsers result; it did, among "
        f"{len(listed)} users"
    )


def _drop_user(iam, user):
    """Teardown-only: a refused CreateUser leaves nothing, so tolerate an already-absent user.

    Scoped to the exact names this check generated -- never a prefix sweep, which would take out
    concurrent runs.
    """
    try:
        iam.delete_user_permissions_boundary(UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    try:
        iam.delete_user(UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
