"""session-policy-intersects-the-role-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-policy-intersects-the-role-policy"
GROUP = 'trust_policies'
SERVICES = ['iam']

_ROLE_POLICY = "sim2real-behav-sess-role-grant"


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


def _with_authorization_details(base, message):
    """IAM's access-denied text: ``base`` followed by a pointer to the per-request authorization
    id, the one opaque token read back from the message; the console link names us-east-1."""
    region = "us-east-1"
    marker = "authorization id: "
    auth_id = message.rsplit(marker, 1)[-1] if message and marker in message else "<absent>"
    return (
        f"{base}. Go to https://{region}.console.aws.amazon.com/iam/home?region={region}"
        f"#/authorization-details/{auth_id} for complete details, or call the "
        f"GetRequestAuthorizationDetails API with the following authorization id: {auth_id}"
    )


def _client_for_session(ctx, creds, service="iam"):
    """A client signing AS the minted session."""
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _assume(sts, caller_arn, role_arn, session_name, *, policy=None, timeout_s=90.0, interval_s=3.0):
    """AssumeRole with the bounded AccessDenied retry a just-written trust policy needs.

    A MalformedPolicyDocument on the session-policy parameter is re-raised immediately rather than
    retried: an emulator that rejects the parameter outright is a fidelity gap, not a transient.
    """
    deadline = time.monotonic() + timeout_s
    # The denial AWS answers while the just-written trust policy has not reached every replica.
    denial = f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: {role_arn}"
    kw = {"RoleArn": role_arn, "RoleSessionName": session_name}
    if policy is not None:
        kw["Policy"] = policy
    last = None
    while True:
        try:
            return sts.assume_role(**kw)["Credentials"]
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message") or ""
            propagating = last == "AccessDenied" and message in (
                denial, _with_authorization_details(denial, message)
            )
            if not propagating or time.monotonic() >= deadline:
                raise AssertionError(
                    f"AssumeRole on {role_arn!r} (session policy: {policy is not None}) failed with "
                    f"{last!r}: {message!r}"
                ) from exc
            time.sleep(interval_s)


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


def _session_policy(action, resource):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}],
    })


def _denial_message(fn):
    """Error.Message of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Message") or ""
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "plane:control",
    "cap:c7",
)
def run(ctx) -> None:
    """A session policy passed to sts:AssumeRole intersects the role policy: an action both allow
    succeeds, while an action only the role allows and one only the session policy grants each fail
    with AccessDenied and the exact message."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]

    role = ctx.unique_name("sim2real-behav-sess-role-")
    role_arn = iam.create_role(
        RoleName=role,
        Path="/",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))

    iam.put_role_policy(
        RoleName=role,
        PolicyName=_ROLE_POLICY,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:GetRole", "iam:ListAttachedRolePolicies"],
                "Resource": role_arn,
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role, PolicyName=_ROLE_POLICY))

    # --- Baseline, with NO session policy: the role policy alone grants both. This is the positive
    #     control for everything below, and sessions need no cleanup -- they expire on their own.
    #     The role's permission policy replicates per-replica after AssumeRole already succeeded on
    #     the trust policy, and IAM reports neither as effective, so each leg expecting a fresh grant
    #     to work is a bounded poll on that success and raises on non-convergence.
    baseline = _client_for_session(
        ctx, _assume(sts, identity["Arn"], role_arn, "sim2real-behav-sess-base", timeout_s=_budget_s(ctx, 90.0))
    )
    base_get = _poll(
        lambda: _error_code(lambda: baseline.get_role(RoleName=role)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the role policy becomes effective for iam:GetRole on the baseline session",
    )
    assert base_get == "UNEXPECTED_SUCCESS", (
        f"the role policy grants iam:GetRole, so the unrestricted session must succeed; got "
        f"{base_get!r}"
    )
    base_list = _poll(
        lambda: _error_code(lambda: baseline.list_attached_role_policies(RoleName=role)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the role policy becomes effective for iam:ListAttachedRolePolicies",
    )
    assert base_list == "UNEXPECTED_SUCCESS", (
        f"the role policy grants iam:ListAttachedRolePolicies, so the unrestricted session must "
        f"succeed; got {base_list!r}"
    )

    # --- Break exactly one thing: a session policy that narrows to iam:GetRole only.
    narrowed = _client_for_session(
        ctx,
        _assume(
            sts,
            identity["Arn"],
            role_arn,
            "sim2real-behav-sess-narrow",
            policy=_session_policy("iam:GetRole", role_arn),
            timeout_s=_budget_s(ctx, 90.0),
        ),
    )
    narrow_get = _poll(
        lambda: _error_code(lambda: narrowed.get_role(RoleName=role)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the narrowed session keeps the action inside the intersection",
    )
    assert narrow_get == "UNEXPECTED_SUCCESS", (
        f"iam:GetRole is inside the intersection of both documents, so the narrowed session must "
        f"still succeed; got {narrow_get!r}"
    )
    narrow_list = _error_code(lambda: narrowed.list_attached_role_policies(RoleName=role))
    assert narrow_list == "AccessDenied", (
        f"iam:ListAttachedRolePolicies is allowed by the role policy but absent from the session "
        f"policy, so it must be refused with exactly AccessDenied; got {narrow_list!r} -- an "
        f"emulator that ignores the Policy parameter over-permits here"
    )
    narrow_msg = _denial_message(lambda: narrowed.list_attached_role_policies(RoleName=role))
    narrow_arn = f"arn:aws:sts::{account_id}:assumed-role/{role}/sim2real-behav-sess-narrow"
    expected_msg = _with_authorization_details(
        f"User: {narrow_arn} is not authorized to perform: iam:ListAttachedRolePolicies on "
        f"resource: role {role} because no session policy allows the "
        "iam:ListAttachedRolePolicies action",
        narrow_msg,
    )
    assert narrow_msg == expected_msg, f"expected message {expected_msg!r}, got {narrow_msg!r}"

    # --- A session policy grants NOTHING on its own: the same claim from the other direction.
    granting = _client_for_session(
        ctx,
        _assume(
            sts,
            identity["Arn"],
            role_arn,
            "sim2real-behav-sess-grant",
            policy=_session_policy("iam:CreateUser", "*"),
            timeout_s=_budget_s(ctx, 90.0),
        ),
    )
    probe_user = ctx.unique_name("sim2real-behav-sess-probe-")
    created = None
    try:
        granting.create_user(UserName=probe_user, Path="/")
    except ClientError as exc:
        grant_code = exc.response.get("Error", {}).get("Code")
        grant_msg = exc.response.get("Error", {}).get("Message") or ""
    else:
        # If the service wrongly ACCEPTED this, the user now exists; register its cleanup before the
        # assertion below aborts the check.
        created = probe_user
        grant_code = "UNEXPECTED_SUCCESS"
        grant_msg = ""
    if created is not None:
        ctx.on_cleanup(lambda: iam.delete_user(UserName=created))
    assert grant_code == "AccessDenied", (
        f"the role policy does not grant iam:CreateUser, so a session policy granting it must confer "
        f"nothing and the call must be refused with exactly AccessDenied; got {grant_code!r} -- the "
        f"combination is an intersection, not a union"
    )
    grant_arn = f"arn:aws:sts::{account_id}:assumed-role/{role}/sim2real-behav-sess-grant"
    expected_grant_msg = _with_authorization_details(
        f"User: {grant_arn} is not authorized to perform: iam:CreateUser on resource: "
        f"arn:aws:iam::{account_id}:user/{probe_user} because no identity-based policy allows "
        "the iam:CreateUser action",
        grant_msg,
    )
    assert grant_msg == expected_grant_msg, (
        f"expected message {expected_grant_msg!r}, got {grant_msg!r}"
    )

    # --- The baseline session still works at the end, so none of the above is drift.
    still = _poll(
        lambda: _error_code(lambda: baseline.list_attached_role_policies(RoleName=role)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the unrestricted session still succeeds at the end of the check",
    )
    assert still == "UNEXPECTED_SUCCESS", (
        f"the unrestricted session must still succeed at both actions at the end of the check; "
        f"iam:ListAttachedRolePolicies returned {still!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
