"""key-policy-delegation-is-required-for-an-identity-policy-grant."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "key-policy-delegation-is-required-for-an-identity-policy-grant"
GROUP = "auth_enforcement"
SERVICES = ["iam", "kms"]

_IDENTITY = "sim2real-behav-kms-identity-grant"
# Enough for the check to manage the key and for the principal to read its metadata; deliberately
# WITHOUT kms:Encrypt, which is the action under test. kms:PutKeyPolicy keeps the policy editable,
# which is what satisfies KMS's lockout-safety check.
_MANAGEMENT = [
    "kms:DescribeKey",
    "kms:GetKeyPolicy",
    "kms:PutKeyPolicy",
    "kms:ScheduleKeyDeletion",
    "kms:CancelKeyDeletion",
    "kms:Decrypt",
    "kms:TagResource",
]
_SUBJECT = "kms:Encrypt"
_PLAINTEXT = b"sim2real-kms-delegation-payload-0123456789"
_MARK = [{"TagKey": "sim2real", "TagValue": CHECK}]


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An identity policy Allowing kms:Encrypt is refused with AccessDenied while the key policy does
    not delegate to the account; adding that delegation makes the call return ciphertext that
    decrypts to the exact plaintext, and removing it restores the refusal."""
    iam = ctx.client("iam")
    kms = ctx.client("kms")

    user = ctx.unique_name("sim2real-kmsdeleg-user-")
    iam.create_user(UserName=user, Path="/", Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]
    root_arn = f"arn:aws:iam::{user_arn.split(':')[4]}:root"

    key_meta = kms.create_key(
        Description=f"sim2real {CHECK}",
        Policy=json.dumps(_key_policy(root_arn, _MANAGEMENT)),
        Tags=_MARK,
    )["KeyMetadata"]
    key_arn = key_meta["Arn"]
    ctx.on_cleanup(lambda: _schedule_deletion(kms, key_arn))

    # The key policy is what it was asked to be, read back through a different operation.
    stored = json.loads(kms.get_key_policy(KeyId=key_arn, PolicyName="default")["Policy"])
    stored_actions = stored["Statement"][0]["Action"]
    assert _SUBJECT not in stored_actions, (
        f"the key policy's delegation must NOT include {_SUBJECT} before its absence is asserted to "
        f"block anything; GetKeyPolicy reports the delegated actions as {stored_actions!r}"
    )

    # The identity policy DOES grant the subject action. It is the whole point: everywhere else in
    # the account this would be sufficient.
    iam.put_user_policy(
        UserName=user,
        PolicyName=_IDENTITY,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [_SUBJECT, "kms:DescribeKey"],
                "Resource": key_arn,
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=_IDENTITY))

    access_key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user, AccessKeyId=access_key["AccessKeyId"])
    )
    as_user = _signing_as(ctx, "kms", access_key)

    # --- Control: kms:DescribeKey is granted by BOTH documents, so it must work. This proves the
    #     credential, the endpoint and the key are all healthy for this principal -- the refusal below
    #     can then only be about the missing delegation.
    ready = _poll(
        lambda: _outcome(lambda: as_user.describe_key(KeyId=key_arn)),
        lambda o: o == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="kms:DescribeKey, delegated by the key policy and granted by the identity policy",
    )
    assert ready == "OK", (
        f"kms:DescribeKey is allowed by the key policy's delegation AND by the identity policy, so it "
        f"must succeed before anything is concluded from an Encrypt refusal; expected 'OK', got "
        f"{ready!r}"
    )

    # --- The claim: the identity policy grants Encrypt; the key policy does not delegate it.
    refusal = (
        "AccessDeniedException",
        f"User: {user_arn} is not authorized to perform: {_SUBJECT} on resource: {key_arn} "
        f"because no resource-based policy allows the {_SUBJECT} action",
    )
    refused = _rejected_error(
        lambda: as_user.encrypt(KeyId=key_arn, Plaintext=_PLAINTEXT)
    )
    assert refused == refusal, (
        f"the identity policy Allows {_SUBJECT} on {key_arn!r} but the key policy delegates only "
        f"{stored_actions!r} to the account, so the real signed call must be refused with exactly "
        f"{refusal!r}; got {refused!r} -- an emulator that applies the same-account UNION "
        f"rule to a KMS key grants access here that AWS does not"
    )

    # --- Break exactly one thing: add the subject action to the key policy's delegation. The
    #     identity policy is untouched, the principal is untouched, the request is byte-identical.
    kms.put_key_policy(
        KeyId=key_arn,
        PolicyName="default",
        Policy=json.dumps(_key_policy(root_arn, _MANAGEMENT + [_SUBJECT])),
    )
    delegated = json.loads(kms.get_key_policy(KeyId=key_arn, PolicyName="default")["Policy"])
    assert _SUBJECT in delegated["Statement"][0]["Action"], (
        f"the delegation must observably include {_SUBJECT} before its effect is asserted; "
        f"GetKeyPolicy reports {delegated['Statement'][0]['Action']!r}"
    )

    ciphertext = _poll(
        lambda: _encrypted(as_user, key_arn),
        lambda v: isinstance(v, bytes),
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="delegating the action to the account lets the identity-policy grant take effect",
    )
    assert isinstance(ciphertext, bytes) and ciphertext, (
        f"with {_SUBJECT} delegated, the identical real signed Encrypt must succeed and return a "
        f"non-empty CiphertextBlob; got {ciphertext!r}"
    )
    assert ciphertext != _PLAINTEXT, (
        f"the ciphertext must not be the plaintext -- a target that echoes the payload back has not "
        f"encrypted anything; got {ciphertext!r}"
    )

    # --- Terminal read at the destination, through a different operation, on real bytes.
    decrypted = kms.decrypt(CiphertextBlob=ciphertext)
    assert decrypted["Plaintext"] == _PLAINTEXT, (
        f"the ciphertext the minted principal produced must decrypt back to the exact plaintext: "
        f"expected {_PLAINTEXT!r}, Decrypt returned {decrypted['Plaintext']!r}"
    )
    assert decrypted["KeyId"] == key_arn, (
        f"Decrypt must attribute the ciphertext to the key this check created: expected {key_arn!r}, "
        f"got {decrypted['KeyId']!r}"
    )

    # --- Restore: withdraw the delegation. The refusal must return, so the grant came from the key
    #     policy and the identity policy was never sufficient on its own.
    kms.put_key_policy(
        KeyId=key_arn,
        PolicyName="default",
        Policy=json.dumps(_key_policy(root_arn, _MANAGEMENT)),
    )
    withdrawn = _poll(
        lambda: _outcome(lambda: as_user.encrypt(KeyId=key_arn, Plaintext=_PLAINTEXT)),
        lambda o: o == "AccessDeniedException",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="withdrawing the delegation restores the refusal",
    )
    assert withdrawn == "AccessDeniedException", (
        f"removing {_SUBJECT} from the key policy's delegation must refuse the identical call with "
        f"exactly AccessDeniedException again; got {withdrawn!r} -- an emulator whose effective "
        f"permissions only ever widen fails here"
    )
    rewithdrawn = _rejected_error(
        lambda: as_user.encrypt(KeyId=key_arn, Plaintext=_PLAINTEXT)
    )
    assert rewithdrawn == refusal, (
        f"the restored refusal must carry the same code and message as the first one: expected "
        f"{refusal!r}, got {rewithdrawn!r}"
    )
    # ... and the still-delegated action is unaffected, so the withdrawal was scoped.
    unaffected = _outcome(lambda: as_user.describe_key(KeyId=key_arn))
    assert unaffected == "OK", (
        f"kms:DescribeKey is still delegated and still granted, so it must keep working while "
        f"{_SUBJECT} is refused; expected 'OK', got {unaffected!r}"
    )


# ===== helpers =====
def _key_policy(root_arn, actions):
    """A key policy delegating exactly ``actions`` to the account root and nothing to anyone else.

    kms:PutKeyPolicy is always in the set, which is what keeps the policy editable and satisfies
    KMS's lockout-safety check without needing BypassPolicyLockoutSafetyCheck.
    """
    return {
        "Version": "2012-10-17",
        "Id": "sim2real-delegation-scope",
        "Statement": [{
            "Sid": "DelegateToAccount",
            "Effect": "Allow",
            "Principal": {"AWS": root_arn},
            "Action": list(actions),
            "Resource": "*",
        }],
    }


def _outcome(fn):
    """``"OK"`` on success, else the AWS error code.

    ``"OK"`` is a truthy sentinel no AWS error code can equal, and every caller either feeds it to
    ``_poll`` (which RAISES on timeout, so a target that never converges cannot pass) or asserts it
    against an exact expected value. Refusals asserted WITHOUT a preceding poll go through
    ``_rejected_error``, which raises on an unexpected success.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"
    return "OK"


def _rejected_error(fn):
    """``(code, message)`` of a call real AWS MUST refuse; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (err.get("Code") or "NO_ERROR_CODE", err.get("Message"))
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry with a deadline. RAISES on timeout -- never returns its last value on failure.

    An IAM policy write reaching the KMS authorizer, and a key-policy write becoming effective, are
    both genuinely asynchronous and neither service reports the propagation as done.
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


def _encrypted(client, key_arn):
    """The CiphertextBlob as bytes, or the error code as a str.

    The poll predicate demands ``bytes``, so an error code can never satisfy it and the poll's
    timeout RAISES -- a refusal is never mistaken for a ciphertext.
    """
    try:
        return client.encrypt(KeyId=key_arn, Plaintext=_PLAINTEXT)["CiphertextBlob"]
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"


def _schedule_deletion(kms, key_arn):
    """Teardown: KMS keys cannot be deleted immediately; 7 days is the minimum pending window.

    Tolerates a key already pending deletion, which is what a re-run of this check would find.
    """
    try:
        kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in ("KMSInvalidStateException", "NotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
