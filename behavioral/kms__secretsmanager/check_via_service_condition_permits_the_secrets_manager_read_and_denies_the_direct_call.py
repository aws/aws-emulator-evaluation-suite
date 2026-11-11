"""via-service-condition-permits-the-secrets-manager-read-and-denies-the-direct-call."""
from __future__ import annotations

# Secrets Manager reaches KMS through a forward access session carrying kms:ViaService, while the
# caller's direct KMS call carries none, so a StringNotEquals Deny on it blocks only the direct call
# (kms/latest/developerguide/conditions-kms.html).

import hashlib
import json
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "via-service-condition-permits-the-secrets-manager-read-and-denies-the-direct-call"
GROUP = "overly-permissive"
SERVICES = ["kms", "secretsmanager"]

_DENY_SID = "sim2realRequireViaSecretsManager"
_DENIED_ACTIONS = [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:GenerateDataKey",
    "kms:GenerateDataKey*",
    "kms:ReEncrypt*",
]
ERR_ACCESS_DENIED = "AccessDeniedException"
_SUCCEEDED = "<the call succeeded>"


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7 days is the AWS minimum window)."""
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    for attempt in range(4):
        try:
            kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "KMSInvalidStateException":
                return
            if code not in ("ThrottlingException", "KMSInternalException") or attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))


def _restore_key_policy(kms, key_id: str, policy: str) -> None:
    """Put back the permissive policy. Registered so LIFO cleanup runs it BEFORE key deletion."""
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=policy)


def _reap_secret(sm, secret_id: str) -> None:
    """Delete the secret this check created, with no recovery window so nothing is left behind."""
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _poll_until(fn, predicate, *, timeout_s: float, interval_s: float = 5.0, what: str = ""):
    """Poll fn() until predicate(value) is true. Returns the value, or RAISES on timeout."""
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last saw {last!r}")


def _direct_outcome(kms, key_arn: str):
    """(_SUCCEEDED, "") if a DIRECT kms:GenerateDataKey succeeds, else (Error.Code, Message)."""
    try:
        kms.generate_data_key(KeyId=key_arn, KeySpec="AES_256")
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    return _SUCCEEDED, ""


def _explicit_deny_message(caller_arn: str, action: str, key_arn: str) -> str:
    return (
        f"User: {caller_arn} is not authorized to perform: {action} on resource: {key_arn} "
        f"with an explicit deny in a resource-based policy"
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """kms:ViaService tells HOW the KMS request arrived: a Deny unless it came via Secrets Manager.

    The caller's direct kms:GenerateDataKey is AccessDeniedException while a NEW secret version
    round-trips via Secrets Manager byte-identically; removing the Deny re-allows the direct call.
    """
    kms = ctx.client("kms")
    sm = ctx.client("secretsmanager")
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]

    via_service = f"secretsmanager.{ctx.region}.amazonaws.com"

    cmk = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-viaservice-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-viaservice-secretsmanager"}],
    )["KeyMetadata"]
    key_arn, key_id = cmk["Arn"], cmk["KeyId"]
    ctx.on_cleanup(lambda: _teardown_key(kms, key_arn))
    original_policy = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
    # Registered AFTER the deletion so LIFO runs it FIRST.
    ctx.on_cleanup(lambda: _restore_key_policy(kms, key_id, original_policy))

    baseline_secret = "via-service-guarded-" + os.urandom(8).hex()
    created = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-viaservice-secret-"),
        SecretString=baseline_secret,
        KmsKeyId=key_arn,
        Description="sim2real behavioral check: kms:ViaService gating",
        Tags=[{"Key": "sim2real", "Value": "kms-viaservice-secretsmanager"}],
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: _reap_secret(sm, secret_arn))

    # --- Baseline: BOTH routes work before the one thing is broken. Without this leg, "the direct
    # call is denied" is indistinguishable from "this account cannot use KMS at all".
    code, message = _direct_outcome(kms, key_arn)
    assert code == _SUCCEEDED, (
        f"baseline: the direct kms:GenerateDataKey must succeed before the ViaService Deny is "
        f"applied; got {code!r}: {message!r}"
    )
    baseline_read = sm.get_secret_value(SecretId=secret_arn)
    assert baseline_read["SecretString"] == baseline_secret, (
        f"baseline: the Secrets Manager read must work before the Deny; digest "
        f"{_digest(baseline_read['SecretString'])} != {_digest(baseline_secret)}"
    )
    baseline_version = baseline_read["VersionId"]

    # --- Break exactly one thing: cryptographic use only when the request arrived VIA Secrets
    # Manager. kms:PutKeyPolicy and kms:ScheduleKeyDeletion are deliberately NOT in the denied
    # action list, so the key stays manageable and this is reversible.
    denied = json.loads(original_policy)
    denied["Statement"].append(
        {
            "Sid": _DENY_SID,
            "Effect": "Deny",
            "Principal": {"AWS": "*"},
            "Action": _DENIED_ACTIONS,
            "Resource": "*",
            "Condition": {"StringNotEquals": {"kms:ViaService": [via_service]}},
        }
    )
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(denied))
    readback = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    assert any(s.get("Sid") == _DENY_SID for s in readback["Statement"]), (
        f"the {_DENY_SID} statement was not persisted, so the rest of this check would grade "
        f"nothing: {readback!r}"
    )

    code, message = _poll_until(
        lambda: _direct_outcome(kms, key_arn),
        lambda pair: pair[0] != _SUCCEEDED,
        timeout_s=120,
        what=(
            f"the direct kms:GenerateDataKey to start being refused — the Deny fires unless "
            f"kms:ViaService equals {via_service}, and a direct call carries no such value"
        ),
    )
    assert code == ERR_ACCESS_DENIED, (
        f"the DIRECT call must be refused with {ERR_ACCESS_DENIED}; got {code!r}: {message!r}"
    )
    expected = _explicit_deny_message(caller_arn, "kms:GenerateDataKey", key_arn)
    assert message == expected, (
        f"the refusal must attribute itself to the explicit Deny in the key policy rather than "
        f"reading as a missing-permission error: expected {expected!r}, got {message!r}"
    )

    # --- THE ASSERTION: the same principal, the same key, the same crypto action — but routed
    # through Secrets Manager — still works, and it works for a write that needs a FRESH data key.
    new_secret = "rotated-via-service-" + os.urandom(8).hex()
    assert new_secret != baseline_secret, (new_secret, baseline_secret)
    put = sm.put_secret_value(SecretId=secret_arn, SecretString=new_secret)
    assert put["VersionId"] != baseline_version, (
        f"PutSecretValue must create a NEW version (which forces a fresh KMS GenerateDataKey "
        f"through the service); got the baseline version {baseline_version!r} back"
    )

    # Terminal independent read at the consumer, via a DIFFERENT operation than the write.
    read_back = sm.get_secret_value(SecretId=secret_arn)
    assert _digest(read_back["SecretString"]) == _digest(new_secret), (
        f"while the direct KMS path is denied, the Secrets Manager read of the NEW version must "
        f"return the byte-identical plaintext; digest {_digest(read_back['SecretString'])} != "
        f"{_digest(new_secret)}"
    )
    assert read_back["VersionId"] == put["VersionId"], (
        f"the current version must be the one just written: {read_back['VersionId']!r} != "
        f"{put['VersionId']!r}"
    )
    # The older version is still decryptable through the service too, so nothing about the Deny
    # broke the secret's existing material.
    old = sm.get_secret_value(SecretId=secret_arn, VersionId=baseline_version)
    assert _digest(old["SecretString"]) == _digest(baseline_secret), (
        f"the baseline version must still decrypt through Secrets Manager; digest "
        f"{_digest(old['SecretString'])} != {_digest(baseline_secret)}"
    )

    # --- Effect scoping: the direct denial covers Decrypt as well, so the earlier refusal was
    # about the route and not about GenerateDataKey specifically.
    try:
        kms.encrypt(KeyId=key_arn, Plaintext=b"direct-encrypt-should-be-denied")
    except ClientError as exc:
        encrypt_err = exc.response.get("Error", {})
    else:
        raise AssertionError(
            f"a direct kms:Encrypt SUCCEEDED while the ViaService Deny is live; real AWS refuses it "
            f"with {ERR_ACCESS_DENIED}"
        )
    assert encrypt_err.get("Code") == ERR_ACCESS_DENIED, (
        f"a direct kms:Encrypt must also be refused with {ERR_ACCESS_DENIED} while the ViaService "
        f"Deny is live; got {encrypt_err!r}"
    )
    expected = _explicit_deny_message(caller_arn, "kms:Encrypt", key_arn)
    assert encrypt_err.get("Message") == expected, (
        f"the direct kms:Encrypt refusal must name the explicit Deny: expected {expected!r}, got "
        f"{encrypt_err.get('Message')!r}"
    )

    # --- Restore the one broken thing and demand the withheld capability back.
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=original_policy)
    code, message = _poll_until(
        lambda: _direct_outcome(kms, key_arn),
        lambda pair: pair[0] == _SUCCEEDED,
        timeout_s=120,
        what="the identical direct kms:GenerateDataKey to succeed once the ViaService Deny is gone",
    )
    assert code == _SUCCEEDED, (
        f"positive control: removing the Deny must make the byte-identical direct call succeed; "
        f"got {code!r}: {message!r}"
    )
    final = sm.get_secret_value(SecretId=secret_arn)
    assert _digest(final["SecretString"]) == _digest(new_secret), (
        f"the secret must be unchanged by any of this; digest {_digest(final['SecretString'])} != "
        f"{_digest(new_secret)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
