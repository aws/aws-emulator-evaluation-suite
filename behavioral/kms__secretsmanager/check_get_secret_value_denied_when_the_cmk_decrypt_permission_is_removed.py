"""get-secret-value-denied-when-the-cmk-decrypt-permission-is-removed."""

from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-secret-value-denied-when-the-cmk-decrypt-permission-is-removed"

GROUP = "overly-permissive"

SERVICES = ["kms", "secretsmanager"]

_SCENARIO = "secretsmanager-cmk-decrypt-denied"


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A kms:Decrypt Deny on a secret's CMK makes GetSecretValue fail AccessDeniedException while
    DescribeSecret and ListSecrets keep working; restoring the key policy makes the same plaintext
    readable again with no new version.
    """
    sm = ctx.client("secretsmanager")
    kms = ctx.client("kms")

    # The DEFAULT key policy (account root + IAM) keeps the check from locking itself out of its key.
    key = kms.create_key(
        Description="sim2real behavioral check: CMK decrypt denial for Secrets Manager",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=_kms_tags(_SCENARIO),
    )
    key_arn = key["KeyMetadata"]["Arn"]
    key_id = key["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _schedule_key_deletion(ctx, key_id))

    original_policy = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
    # Restore the permissive policy BEFORE anything else is torn down: cleanup is LIFO, and a
    # ScheduleKeyDeletion issued while the deny is live would itself be at risk.
    ctx.on_cleanup(lambda: _restore_key_policy(ctx, key_id, original_policy))

    plaintext = "cmk-guarded-credential-" + hashlib.sha256(key_arn.encode()).hexdigest()[:12]
    name = ctx.unique_name("sim2real-behav-cmkdeny-secret-")
    created = sm.create_secret(
        Name=name,
        SecretString=plaintext,
        KmsKeyId=key_arn,
        Description="sim2real behavioral check: CMK-encrypted secret",
        Tags=_sim2real_tags(_SCENARIO),
    )
    arn = created["ARN"]
    ctx.on_cleanup(lambda: _reap_secret(ctx, arn))

    baseline = sm.get_secret_value(SecretId=arn)
    assert baseline["SecretString"] == plaintext, (
        f"baseline: the read through the CMK must work before the deny is applied, got "
        f"{baseline['SecretString']!r}"
    )
    baseline_version = baseline["VersionId"]

    # ListSecrets is eventually consistent: a fresh secret takes seconds to appear in the list, so
    # the baseline is established BEFORE the deny to make the later assertion mean "not removed".
    _poll_until(
        lambda: _list_secret_arns(sm, name),
        lambda found: arn in found,
        timeout_s=90.0,
        interval_s=3.0,
        description=f"the freshly created secret {name} to appear in ListSecrets",
    )

    # The Deny names ONLY kms:Decrypt, so PutKeyPolicy and ScheduleKeyDeletion stay available and
    # the change is reversible.
    denied_policy = json.loads(original_policy)
    denied_policy["Statement"].append(
        {
            "Sid": "sim2realDenyDecrypt",
            "Effect": "Deny",
            "Principal": {"AWS": "*"},
            "Action": "kms:Decrypt",
            "Resource": "*",
        }
    )
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(denied_policy))

    readback = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    assert any(s.get("Sid") == "sim2realDenyDecrypt" for s in readback["Statement"]), (
        f"the deny statement was not persisted, so the rest of the check would grade nothing: "
        f"{readback!r}"
    )

    # KMS key-policy changes are eventually consistent; poll for the denial and fail if it never
    # arrives.
    code, err = _poll_until(
        lambda: _error_code(lambda: sm.get_secret_value(SecretId=arn)),
        lambda pair: pair[0] is not None,
        timeout_s=90.0,
        interval_s=3.0,
        description=f"the kms:Decrypt Deny on {key_arn} to become effective on GetSecretValue",
    )
    msg = err.get("Error", {}).get("Message", "") if isinstance(err, dict) else ""
    assert code == "AccessDeniedException", (
        f"a denied kms:Decrypt must surface on GetSecretValue as AccessDeniedException, got "
        f"{code!r}: {msg!r}"
    )
    assert msg == "Access to KMS is not allowed", (
        f"the refusal must attribute itself to KMS with the exact message 'Access to KMS is not "
        f"allowed' rather than reading as a generic Secrets Manager denial: {msg!r}"
    )

    # Secret metadata is not encrypted under the CMK, so it stays readable.
    desc = sm.describe_secret(SecretId=arn)
    assert desc["ARN"] == arn and desc["KmsKeyId"] == key_arn, (
        f"DescribeSecret must still resolve while the key is undecryptable -- secret METADATA is "
        f"not encrypted under the CMK: {desc!r}"
    )
    listed = _list_secret_arns(sm, name)
    assert arn in listed, (
        f"ListSecrets enumerated this secret before the deny and must still enumerate it now -- an "
        f"undecryptable key must not hide the row; the filtered, fully-paginated listing held "
        f"{sorted(listed)!r}"
    )

    # Positive control: restore the original key policy.
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=original_policy)
    restored = _poll_until(
        lambda: _error_code(lambda: sm.get_secret_value(SecretId=arn)),
        lambda pair: pair[0] is None,
        timeout_s=120.0,
        interval_s=3.0,
        description="the read to succeed again after the original key policy was restored",
    )
    restored_code, restored_resp = restored
    assert restored_code is None, (
        f"positive control: restoring the key policy must make the read succeed again, got "
        f"{restored_code!r}"
    )
    assert _digest(restored_resp["SecretString"]) == _digest(plaintext), (
        f"the plaintext recovered after restoring the key policy must be byte-identical; digest "
        f"{_digest(restored_resp['SecretString'])} != {_digest(plaintext)}"
    )
    assert restored_resp["VersionId"] == baseline_version, (
        f"no new version may have been created by any of this: {restored_resp['VersionId']!r} != "
        f"{baseline_version!r}"
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _sim2real_tags(scenario: str) -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": scenario},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _kms_tags(scenario: str) -> list[dict[str, str]]:
    """KMS spells tags TagKey/TagValue, not Key/Value."""
    return [
        {"TagKey": "sim2real", "TagValue": scenario},
        {"TagKey": "sim2real:managed", "TagValue": "true"},
    ]


def _error_code(fn):
    """Call fn(); return (error_code, response_or_result). On an unexpected SUCCESS return
    (None, result) -- never a falsy sentinel that could be read as a code."""
    try:
        return None, fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {description}; last observation was {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _list_secret_arns(sm, name_prefix: str) -> set[str]:
    """Fully paginated ListSecrets; the name filter narrows results but does not bound them to
    one page."""
    found: set[str] = set()
    token = None
    while True:
        kwargs: dict = {"Filters": [{"Key": "name", "Values": [name_prefix]}], "MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        resp = sm.list_secrets(**kwargs)
        found.update(s["ARN"] for s in resp.get("SecretList", []))
        token = resp.get("NextToken")
        if not token:
            return found


def _restore_key_policy(ctx, key_id: str, policy: str) -> None:
    try:
        ctx.client("kms").put_key_policy(KeyId=key_id, PolicyName="default", Policy=policy)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NotFoundException",):
            raise RuntimeError(
                f"could not restore the key policy on {key_id}: {exc}"
            ) from exc


def _schedule_key_deletion(ctx, key_id: str) -> None:
    """Schedule deletion with the 7-day minimum pending window AWS enforces."""
    try:
        ctx.client("kms").schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code != "KMSInvalidStateException":
            raise RuntimeError(
                f"schedule_key_deletion({key_id}) failed with {code}: {exc}"
            ) from exc


def _reap_secret(ctx, secret_id: str, timeout_s: float = 60.0) -> None:
    """Force-delete a secret and poll until it is really gone.

    ForceDeleteWithoutRecovery is mandatory: a plain DeleteSecret imposes a 7-30 day recovery
    window, so the secret would outlive the run.
    """
    sm = ctx.client("secretsmanager")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code in ("ThrottlingException", "InternalServiceError"):
                time.sleep(2.0)
                continue
            teardown_code = exc.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("ResourceNotFoundException",):
                raise RuntimeError(
                    f"delete_secret({secret_id}) failed with {code}: {exc}"
                ) from exc
            return
    while time.monotonic() < deadline:
        try:
            sm.describe_secret(SecretId=secret_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
        time.sleep(2.0)
    raise RuntimeError(f"secret {secret_id} still present {timeout_s}s after "
        f"ForceDeleteWithoutRecovery; it bills $0.40/month until reaped")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
