"""sep-kms-key-scope-grant-context-equals-matches-reordered-context-but-absent-context-denied."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-kms-key-scope-grant-context-equals-matches-reordered-context-but-absent-context-denied"
GROUP = "key-separation"
SERVICES = ["kms"]

_CONSTRAINT = {"tenant": "acme", "purpose": "invoice", "zone": "west"}


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An EncryptionContextEquals Decrypt grant lets a permission-less user decrypt with the context
    pairs reordered, and refuses a context-free blob with AccessDeniedException.
    """
    iam = ctx.client("iam")
    kms = ctx.client("kms")

    user = ctx.unique_name("sim2real-sep-ctxgrantee-")
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": "sep-kms-grant-ctx"}])
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

    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-sep-gctx-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key = meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key, PendingWindowInDays=7))

    pt_ctx, pt_none = b"sep-constrained-payload", b"sep-context-free-payload"
    ct_ctx = kms.encrypt(KeyId=key, Plaintext=pt_ctx, EncryptionContext=_CONSTRAINT)["CiphertextBlob"]
    ct_none = kms.encrypt(KeyId=key, Plaintext=pt_none)["CiphertextBlob"]

    grant = _create_grant(ctx, kms, key, user_arn)
    token = grant["GrantToken"]
    stored = [
        g for page in kms.get_paginator("list_grants").paginate(KeyId=key)
        for g in page["Grants"] if g["GrantId"] == grant["GrantId"]
    ]
    assert len(stored) == 1 and stored[0]["Constraints"] == {"EncryptionContextEquals": _CONSTRAINT}, (
        f"ListGrants must show exactly the constraint that was set; got {stored!r}"
    )

    reordered = dict(reversed(list(_CONSTRAINT.items())))
    # Polled only because a brand-new access key takes a moment to be recognised.
    first = _poll(
        lambda: _outcome(lambda: as_user.decrypt(
            CiphertextBlob=ct_ctx, EncryptionContext=reordered, GrantTokens=[token])),
        lambda o: o == "OK",
        timeout_s=90,
        interval_s=3,
        description="grantee decrypts the constrained blob with the reordered context",
    )
    assert first == "OK", f"the reordered-context decrypt must be authorized by the grant, got {first!r}"
    got = as_user.decrypt(CiphertextBlob=ct_ctx, EncryptionContext=reordered, GrantTokens=[token])
    assert (got["KeyId"], got["Plaintext"]) == (key, pt_ctx), (
        f"the grantee must receive ({key!r}, {pt_ctx!r}); got {(got['KeyId'], got['Plaintext'])!r}"
    )

    # An empty request context must not vacuously satisfy an Equals constraint.
    denied = (
        "AccessDeniedException",
        f"User: {user_arn} is not authorized to perform: kms:Decrypt on resource: {key} because no "
        f"identity-based policy allows the kms:Decrypt action",
    )
    code = _rejected(lambda: as_user.decrypt(CiphertextBlob=ct_none, GrantTokens=[token]))
    assert code == denied, (
        f"an EncryptionContextEquals grant must refuse a context-free decrypt with "
        f"AccessDeniedException, got {code!r}"
    )

    owner = kms.decrypt(CiphertextBlob=ct_none)
    assert owner["Plaintext"] == pt_none, (
        f"the key owner must still decrypt the context-free blob, got {owner['Plaintext']!r}"
    )
    again = as_user.decrypt(CiphertextBlob=ct_ctx, EncryptionContext=_CONSTRAINT, GrantTokens=[token])
    assert again["Plaintext"] == pt_ctx, (
        f"after the refusal the grantee must still decrypt the constrained blob, got "
        f"{again['Plaintext']!r}"
    )


def _create_grant(ctx, kms, key_arn, grantee_arn):
    """CreateGrant for Decrypt under EncryptionContextEquals, retried only while IAM has not yet
    made the new user resolvable (InvalidArnException)."""
    deadline = time.monotonic() + 90
    while True:
        try:
            resp = kms.create_grant(
                KeyId=key_arn, GranteePrincipal=grantee_arn, Operations=["Decrypt"],
                Constraints={"EncryptionContextEquals": _CONSTRAINT},
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
