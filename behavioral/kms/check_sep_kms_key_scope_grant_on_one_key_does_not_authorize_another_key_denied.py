"""sep-kms-key-scope-grant-on-one-key-does-not-authorize-another-key-denied."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-kms-key-scope-grant-on-one-key-does-not-authorize-another-key-denied"
GROUP = "key-separation"
SERVICES = ["kms"]


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Decrypt grant on key A lets a permission-less user decrypt A's blob but not B's
    (AccessDeniedException, with the token and after propagation) until a grant on B is created.
    """
    iam = ctx.client("iam")
    kms = ctx.client("kms")

    user = ctx.unique_name("sim2real-sep-grantee-")
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": "sep-kms-grant-scope"}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]
    access = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=access["AccessKeyId"]))
    as_user = ctx.client(
        "kms",
        creds={
            "aws_access_key_id": access["AccessKeyId"],
            "aws_secret_access_key": access["SecretAccessKey"],
        },
    )

    key_a = _new_key(ctx, kms, "a")
    key_b = _new_key(ctx, kms, "b")
    pt_a, pt_b = b"sep-grant-scope-payload-A", b"sep-grant-scope-payload-B"
    ct_a = kms.encrypt(KeyId=key_a, Plaintext=pt_a)["CiphertextBlob"]
    ct_b = kms.encrypt(KeyId=key_b, Plaintext=pt_b)["CiphertextBlob"]

    grant_a = _create_grant(ctx, kms, key_a, user_arn)
    token_a = grant_a["GrantToken"]

    # Polled only because a brand-new access key takes a moment to be recognised.
    first = _poll(
        lambda: _outcome(lambda: as_user.decrypt(CiphertextBlob=ct_a, GrantTokens=[token_a])),
        lambda o: o == "OK",
        timeout_s=90,
        interval_s=3,
        description="grantee decrypts key A's blob with the grant token",
    )
    assert first == "OK", f"the grantee must decrypt key A's blob with the grant token, got {first!r}"
    got_a = as_user.decrypt(CiphertextBlob=ct_a, GrantTokens=[token_a])
    assert (got_a["KeyId"], got_a["Plaintext"]) == (key_a, pt_a), (
        f"the grantee must receive ({key_a!r}, {pt_a!r}); got {(got_a['KeyId'], got_a['Plaintext'])!r}"
    )

    denied_b = (
        "AccessDeniedException",
        f"User: {user_arn} is not authorized to perform: kms:Decrypt on resource: {key_b} because no "
        f"identity-based policy allows the kms:Decrypt action",
    )
    with_token = _rejected(lambda: as_user.decrypt(CiphertextBlob=ct_b, GrantTokens=[token_a]))
    assert with_token == denied_b, (
        f"key A's grant token presented for key B's blob must be refused with AccessDeniedException, "
        f"got {with_token!r}"
    )
    # Once A's grant has propagated (A's blob decrypts WITHOUT a token), B is still refused.
    propagated = _poll(
        lambda: _outcome(lambda: as_user.decrypt(CiphertextBlob=ct_a)),
        lambda o: o == "OK",
        timeout_s=120,
        interval_s=5,
        description="key A's grant usable without its token (propagated)",
    )
    assert propagated == "OK", f"key A's grant must eventually work without a token, got {propagated!r}"
    no_token = _rejected(lambda: as_user.decrypt(CiphertextBlob=ct_b))
    assert no_token == denied_b, (
        f"after key A's grant has propagated, key B's blob must still be refused with "
        f"AccessDeniedException, got {no_token!r}"
    )

    grant_b = _create_grant(ctx, kms, key_b, user_arn)
    got_b = as_user.decrypt(CiphertextBlob=ct_b, GrantTokens=[grant_b["GrantToken"]])
    assert (got_b["KeyId"], got_b["Plaintext"]) == (key_b, pt_b), (
        f"with a grant on key B the grantee must receive ({key_b!r}, {pt_b!r}); got "
        f"{(got_b['KeyId'], got_b['Plaintext'])!r}"
    )


def _new_key(ctx, kms, label):
    """A fresh symmetric key; its 7-day scheduled deletion is registered before it is returned."""
    meta = kms.create_key(
        Description=ctx.unique_name(f"sim2real-sep-gs-{label}-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    arn = meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7))
    return arn


def _create_grant(ctx, kms, key_arn, grantee_arn):
    """CreateGrant for Decrypt, retried only while IAM has not yet made the new user resolvable
    (CreateGrant validates GranteePrincipal and reports an unresolvable one as InvalidArnException).
    """
    deadline = time.monotonic() + 90
    while True:
        try:
            resp = kms.create_grant(
                KeyId=key_arn, GranteePrincipal=grantee_arn, Operations=["Decrypt"],
                Name=ctx.unique_name("sim2real-sep-grant-"),
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidArnException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"CreateGrant never accepted {grantee_arn!r}: {exc}") from exc
            time.sleep(3)
    grant_id = resp["GrantId"]
    ctx.on_cleanup(lambda: kms.revoke_grant(KeyId=key_arn, GrantId=grant_id))
    return resp


def _outcome(fn):
    """``"OK"`` on success, else the AWS error code."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"
    return "OK"


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded poll to an observable condition; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _rejected(fn):
    """The AWS error code and message of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code") or "NO_ERROR_CODE", err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
