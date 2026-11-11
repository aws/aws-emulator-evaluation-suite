"""trust-policy-denies-assume-role-for-an-unnamed-principal."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trust-policy-denies-assume-role-for-an-unnamed-principal"
GROUP = 'trust_policies'
SERVICES = ['iam']

_MAY_ASSUME = "sim2real-behav-trust-may-assume"


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


def _sts_for_credentials(ctx, access_key_id, secret_access_key):
    """An sts client signing AS the minted principal, on this target's endpoint and region."""
    return ctx.client(
        "sts",
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )


def _create_role_when_principal_resolves(iam, role_name, trust, *, timeout_s=90.0, interval_s=3.0):
    """A trust policy naming a just-created user's ARN is rejected MalformedPolicyDocument until the
    user resolves, so the create is the bounded retry. Returns the role ARN."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return iam.create_role(
                RoleName=role_name, AssumeRolePolicyDocument=trust, Path="/"
            )["Role"]["Arn"]
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            if last != "MalformedPolicyDocument" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _mint(ctx, iam, user, role_arn):
    """A user holding an identity policy that permits sts:AssumeRole on role_arn, plus its key."""
    iam.create_user(UserName=user, Path="/")
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": role_arn}],
    })
    iam.put_user_policy(UserName=user, PolicyName=_MAY_ASSUME, PolicyDocument=document)
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=_MAY_ASSUME))
    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"])
    )
    return _sts_for_credentials(ctx, key["AccessKeyId"], key["SecretAccessKey"])


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "plane:control",
    "cap:c1",
)
def run(ctx) -> None:
    """A trust policy is evaluated against the caller: the user it names assumes the role first, then
    a second user with an identical identity policy is refused with AccessDenied and its exact
    message."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # The role ARN is derived before the role exists, so both identity policies can name it and be
    # byte-identical: the trust policy is then the only thing that differs between the two users.
    role = ctx.unique_name("sim2real-behav-trust-role-")
    role_arn = f"arn:aws:iam::{account_id}:role/{role}"

    named = ctx.unique_name("sim2real-behav-trust-named-")
    other = ctx.unique_name("sim2real-behav-trust-other-")
    as_named = _mint(ctx, iam, named, role_arn)
    as_other = _mint(ctx, iam, other, role_arn)
    named_arn = iam.get_user(UserName=named)["User"]["Arn"]

    named_doc = iam.get_user_policy(UserName=named, PolicyName=_MAY_ASSUME)["PolicyDocument"]
    other_doc = iam.get_user_policy(UserName=other, PolicyName=_MAY_ASSUME)["PolicyDocument"]
    assert named_doc == other_doc, (
        "the two identity policies must be identical so the trust policy is the ONLY possible "
        f"cause of a difference; got {named_doc!r} vs {other_doc!r}"
    )

    created_arn = _create_role_when_principal_resolves(
        iam,
        role,
        json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": named_arn},
                "Action": "sts:AssumeRole",
            }],
        }),
        timeout_s=_budget_s(ctx, 90.0),
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    assert created_arn == role_arn, (
        f"the derived ARN the identity policies name must be the role's real ARN: derived "
        f"{role_arn!r}, created {created_arn!r}"
    )

    # --- Positive control FIRST. IAM exposes no API reporting a trust policy as effective, so the
    #     wait is the bounded AccessDenied retry itself.
    deadline = time.monotonic() + 90.0
    session = None
    last = None
    while session is None:
        try:
            session = as_named.assume_role(
                RoleArn=role_arn, RoleSessionName="sim2real-behav-trust-named"
            )
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            assert time.monotonic() < deadline, (
                f"the user NAMED in the trust policy must be able to assume {role_arn!r}; still "
                f"failing with {last!r} after 90s -- an emulator that denies both users would pass "
                f"the negative below vacuously, which is why this leg gates it"
            )
            time.sleep(3.0)
    assumed = session["AssumedRoleUser"]["Arn"]
    assert assumed.startswith(f"arn:aws:sts::{account_id}:assumed-role/{role}/"), (
        f"the named user's session must be an assumed-role principal for {role!r}; got {assumed!r}"
    )

    # --- Break exactly one thing: the signer. Same request, same target role, same identity policy.
    denied, message = _error(
        lambda: as_other.assume_role(
            RoleArn=role_arn, RoleSessionName="sim2real-behav-trust-other"
        )
    )
    assert denied == "AccessDenied", (
        f"{other!r} is not named in the trust policy, so its identical AssumeRole must be refused "
        f"with exactly AccessDenied; got {denied!r} -- an identity policy alone confers nothing "
        f"when the resource-based trust policy does not name the caller"
    )
    expected = (
        f"User: arn:aws:iam::{account_id}:user/{other} is not authorized to perform: "
        f"sts:AssumeRole on resource: {role_arn}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # --- The named user still succeeds AFTER the denial: the refusal is principal-specific, not a
    #     shared rate limit or a poisoned cache. Bounded poll rather than a single shot, because IAM
    #     replicates both policies per-replica and reports neither as effective; it still raises if
    #     the named user never recovers, which is the failure this leg exists to catch.
    def named_assumes():
        try:
            as_named.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav-trust-named-again")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            return False
        return True

    again = _poll(
        named_assumes,
        lambda ok: ok,
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the named user can still assume the role after the other user's denial",
    )
    assert again is True, (
        "the named user must still be able to assume the role after the other user's denial"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
