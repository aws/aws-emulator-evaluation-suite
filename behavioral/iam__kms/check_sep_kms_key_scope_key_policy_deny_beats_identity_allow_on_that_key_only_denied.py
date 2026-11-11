"""sep-kms-key-scope-key-policy-deny-beats-identity-allow-on-that-key-only-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-kms-key-scope-key-policy-deny-beats-identity-allow-on-that-key-only-denied"
GROUP = "key-separation"
SERVICES = ["iam", "kms"]


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A key-policy Deny on kms:Decrypt beats the identity Allow on that key only: key A's decrypt
    is AccessDeniedException while key B decrypts and Encrypt under A works; dropping the Deny
    restores A's exact plaintext.
    """
    iam = ctx.client("iam")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    root_arn = f"arn:aws:iam::{account}:root"

    user = ctx.unique_name("sim2real-sep-denied-")
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": "sep-kms-deny-beats-allow"}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    key_a = _new_key(ctx, kms, "a", _policy(root_arn, deny_decrypt_for=user_arn))
    key_b = _new_key(ctx, kms, "b", _policy(root_arn, deny_decrypt_for=None))
    stored = json.loads(kms.get_key_policy(KeyId=key_a, PolicyName="default")["Policy"])
    denies = [s for s in stored["Statement"] if s.get("Effect") == "Deny"]
    assert len(denies) == 1 and denies[0]["Action"] == "kms:Decrypt", (
        f"key A's stored policy must carry exactly one Deny on kms:Decrypt; got {denies!r}"
    )

    iam.put_user_policy(
        UserName=user,
        PolicyName="sim2real-sep-allow-kms",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["kms:Encrypt", "kms:Decrypt"],
                "Resource": [key_a, key_b],
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName="sim2real-sep-allow-kms"))
    access = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=access["AccessKeyId"]))
    as_user = ctx.client(
        "kms",
        creds={
            "aws_access_key_id": access["AccessKeyId"],
            "aws_secret_access_key": access["SecretAccessKey"],
        },
    )

    pt_a, pt_b = b"sep-deny-scope-payload-A", b"sep-deny-scope-payload-B"
    ct_a = kms.encrypt(KeyId=key_a, Plaintext=pt_a)["CiphertextBlob"]
    ct_b = kms.encrypt(KeyId=key_b, Plaintext=pt_b)["CiphertextBlob"]

    # Key B shares A's identity-policy statement, so once B decrypts the Allow is effective for A
    # too and A's refusal can only come from its key policy.
    ready = _poll(
        lambda: _outcome(lambda: as_user.decrypt(CiphertextBlob=ct_b)),
        lambda o: o == "OK",
        timeout_s=120,
        interval_s=4,
        description="the identity-policy Allow takes effect on key B",
    )
    assert ready == "OK", f"the user must decrypt key B's blob via its identity policy, got {ready!r}"
    got_b = as_user.decrypt(CiphertextBlob=ct_b)
    assert (got_b["KeyId"], got_b["Plaintext"]) == (key_b, pt_b), (
        f"the user must receive ({key_b!r}, {pt_b!r}); got {(got_b['KeyId'], got_b['Plaintext'])!r}"
    )

    # The claim: same statement allows A, A's key policy denies -> denied.
    expected = (
        "AccessDeniedException",
        f"User: {user_arn} is not authorized to perform: kms:Decrypt on resource: {key_a} "
        f"with an explicit deny in a resource-based policy",
    )
    refused = _rejected_error(lambda: as_user.decrypt(CiphertextBlob=ct_a))
    assert refused == expected, (
        f"key A's explicit Deny must beat the identity-policy Allow with exactly {expected!r}, "
        f"got {refused!r}"
    )
    # Scoped to the denied action: the same user still encrypts under A.
    enc = as_user.encrypt(KeyId=key_a, Plaintext=pt_a)
    assert enc["KeyId"] == key_a, f"Encrypt under key A is not denied and must succeed; got {enc['KeyId']!r}"
    own = kms.decrypt(CiphertextBlob=enc["CiphertextBlob"])
    assert own["Plaintext"] == pt_a, "the user's A-ciphertext must decrypt (as the owner) to its bytes"

    # Repair exactly one thing: drop the Deny from A's key policy.
    kms.put_key_policy(
        KeyId=key_a, PolicyName="default", Policy=json.dumps(_policy(root_arn, deny_decrypt_for=None))
    )
    restored = _poll(
        lambda: _outcome(lambda: as_user.decrypt(CiphertextBlob=ct_a)),
        lambda o: o == "OK",
        timeout_s=120,
        interval_s=4,
        description="removing the key-policy Deny lets the identity Allow through on key A",
    )
    assert restored == "OK", f"with the Deny removed the user must decrypt key A's blob, got {restored!r}"
    got_a = as_user.decrypt(CiphertextBlob=ct_a)
    assert (got_a["KeyId"], got_a["Plaintext"]) == (key_a, pt_a), (
        f"the user must now receive ({key_a!r}, {pt_a!r}); got {(got_a['KeyId'], got_a['Plaintext'])!r}"
    )


def _policy(root_arn, *, deny_decrypt_for):
    """Full delegation to the account root, plus (optionally) a Deny on kms:Decrypt for exactly one
    principal. The Deny names the principal by aws:PrincipalArn, so KMS does not need to resolve a
    brand-new IAM user at CreateKey time."""
    statements = [{
        "Sid": "DelegateToAccount",
        "Effect": "Allow",
        "Principal": {"AWS": root_arn},
        "Action": "kms:*",
        "Resource": "*",
    }]
    if deny_decrypt_for:
        statements.append({
            "Sid": "DenyDecryptForOnePrincipal",
            "Effect": "Deny",
            "Principal": {"AWS": "*"},
            "Action": "kms:Decrypt",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:PrincipalArn": deny_decrypt_for}},
        })
    return {"Version": "2012-10-17", "Statement": statements}


def _new_key(ctx, kms, label, policy):
    """A fresh symmetric key under ``policy``; its scheduled deletion is registered at once."""
    meta = kms.create_key(
        Description=ctx.unique_name(f"sim2real-sep-deny-{label}-"),
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    arn = meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7))
    return arn


def _outcome(fn):
    """``"OK"`` on success, else the AWS error code. Every caller polls to an exact value."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"
    return "OK"


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded poll to an observable condition. RAISES on timeout, never returns a failing value."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _rejected_error(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected SUCCESS raises with the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (err.get("Code") or "NO_ERROR_CODE", err.get("Message"))
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
