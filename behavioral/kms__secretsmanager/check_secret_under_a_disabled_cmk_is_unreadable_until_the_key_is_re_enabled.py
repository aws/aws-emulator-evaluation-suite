"""secret-under-a-disabled-cmk-is-unreadable-until-the-key-is-re-enabled."""

from __future__ import annotations

import hashlib
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "secret-under-a-disabled-cmk-is-unreadable-until-the-key-is-re-enabled"

GROUP = "state-machine"

SERVICES = ["kms", "secretsmanager"]

_SCENARIO = "secretsmanager-cmk-disabled"


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Key STATE gates secret access: with the CMK disabled, GetSecretValue and PutSecretValue fail.

    DescribeSecret still succeeds, the read is DecryptionFailure, and re-enabling the key returns
    the byte-identical plaintext with no new version, so the failed write minted nothing.
    """
    sm = ctx.client("secretsmanager")
    kms = ctx.client("kms")

    key = kms.create_key(
        Description="sim2real behavioral check: disabled CMK gates Secrets Manager access",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=_kms_tags(_SCENARIO),
    )
    key_arn = key["KeyMetadata"]["Arn"]
    key_id = key["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _schedule_key_deletion(ctx, key_id))
    # Re-enable BEFORE anything is deleted: cleanup is LIFO and deleting a secret whose key is
    # disabled is the obvious teardown trap. Registered here, it runs after the secret's reap.
    ctx.on_cleanup(lambda: _enable_key(ctx, key_id))

    plaintext = "disabled-key-credential-" + hashlib.sha256(key_arn.encode()).hexdigest()[:12]
    name = ctx.unique_name("sim2real-behav-cmkdisable-secret-")
    created = sm.create_secret(
        Name=name,
        SecretString=plaintext,
        KmsKeyId=key_arn,
        Description="sim2real behavioral check: secret under a CMK that gets disabled",
        Tags=_sim2real_tags(_SCENARIO),
    )
    arn = created["ARN"]
    ctx.on_cleanup(lambda: _reap_secret(ctx, arn))

    baseline = sm.get_secret_value(SecretId=arn)
    assert baseline["SecretString"] == plaintext, (
        f"baseline: the CMK-encrypted secret must be readable while the key is enabled, got "
        f"{baseline['SecretString']!r}"
    )
    baseline_version = baseline["VersionId"]
    versions_before = _all_version_ids(sm, arn)
    assert versions_before == {baseline_version}, (
        f"baseline: exactly one version must exist before the disable, saw {sorted(versions_before)!r}"
    )

    # --- the transition: disable the key, polled to the observable state -----------------------
    kms.disable_key(KeyId=key_id)
    _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda state: state == "Disabled",
        timeout_s=60.0,
        interval_s=2.0,
        description=f"CMK {key_id} to report KeyState=Disabled",
    )

    # --- read must fail -------------------------------------------------------------------------
    read_code, read_err = _poll_until(
        lambda: _error_code(lambda: sm.get_secret_value(SecretId=arn)),
        lambda pair: pair[0] is not None,
        timeout_s=90.0,
        interval_s=3.0,
        description="GetSecretValue to start refusing once the CMK is disabled",
    )
    read_msg = read_err.get("Error", {}).get("Message", "") if isinstance(read_err, dict) else ""
    # Secrets Manager does NOT reuse a generic
    # InvalidRequestException or AccessDeniedException here: it raises its own DecryptionFailure and
    # relays the wrapped KMS DisabledException in the message. Asserting the exact code is the whole
    # point -- an emulator that surfaces a generic error for a disabled key is a real fidelity gap.
    assert read_code == "DecryptionFailure", (
        f"reading a secret whose CMK is disabled must fail with DecryptionFailure, got "
        f"{read_code!r}: {read_msg!r}"
    )
    expected_read = _relayed_disabled_message("decrypt", key_arn, read_msg)
    assert read_msg == expected_read, (
        f"the refusal must relay KMS's DisabledException for this key, expected {expected_read!r}, "
        f"got {read_msg!r}"
    )

    # --- the write must fail too: the envelope is exercised in both directions -----------------
    # Capture the response rather than asserting inline: if the service wrongly ACCEPTS this, a
    # version now exists and the version-map assertion below is what has to name it.
    write_code, write_result = _error_code(
        lambda: sm.put_secret_value(SecretId=arn, SecretString="value-that-must-never-be-stored")
    )
    # MEASURED: the write side reports EncryptionFailure, the mirror of the read's DecryptionFailure.
    assert write_code == "EncryptionFailure", (
        f"writing a new version under a disabled CMK must also fail, with EncryptionFailure, got "
        f"{write_code!r} / {write_result!r}"
    )
    write_msg = write_result.get("Error", {}).get("Message", "")
    expected_write = _relayed_disabled_message("encrypt", key_arn, write_msg)
    assert write_msg == expected_write, (
        f"the write refusal must relay KMS's DisabledException for this key, expected "
        f"{expected_write!r}, got {write_msg!r}"
    )

    # --- effect scoping + effect absent ---------------------------------------------------------
    desc = sm.describe_secret(SecretId=arn)
    assert desc["KmsKeyId"] == key_arn and desc["ARN"] == arn, (
        f"DescribeSecret must still resolve and still report the key while the key is disabled -- "
        f"metadata is not encrypted under the CMK: {desc!r}"
    )
    assert set(desc["VersionIdsToStages"]) == {baseline_version}, (
        f"the rejected PutSecretValue minted a version: {desc['VersionIdsToStages']!r}"
    )
    assert desc["VersionIdsToStages"][baseline_version] == ["AWSCURRENT"], (
        f"the surviving version must still be the sole AWSCURRENT holder: "
        f"{desc['VersionIdsToStages']!r}"
    )

    # --- the return transition: re-enable and require the plaintext back ------------------------
    kms.enable_key(KeyId=key_id)
    _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda state: state == "Enabled",
        timeout_s=60.0,
        interval_s=2.0,
        description=f"CMK {key_id} to report KeyState=Enabled again",
    )
    after_code, after_enable = _poll_until(
        lambda: _error_code(lambda: sm.get_secret_value(SecretId=arn)),
        lambda pair: pair[0] is None,
        timeout_s=120.0,
        interval_s=3.0,
        description="GetSecretValue to succeed again after the CMK was re-enabled",
    )
    assert after_code is None, (
        f"re-enabling the key must restore the read, got {after_code!r}"
    )
    assert _digest(after_enable["SecretString"]) == _digest(plaintext), (
        f"the plaintext must survive a disable/enable cycle byte for byte; digest "
        f"{_digest(after_enable['SecretString'])} != {_digest(plaintext)}"
    )
    assert after_enable["VersionId"] == baseline_version, (
        f"no new version may result from the cycle: {after_enable['VersionId']!r} != "
        f"{baseline_version!r}"
    )



def _relayed_disabled_message(verb: str, key_arn: str, actual: str) -> str:
    """The exact message Secrets Manager returns when KMS refuses a disabled key.

    Secrets Manager embeds the KMS call's request id, the only per-call token in the text. It is
    taken from the actual message and must parse as a UUID; everything else is fixed or built
    from the key this check created.
    """
    _, _, tail = actual.partition("; Request ID: ")
    request_id = tail[:36]
    try:
        uuid.UUID(request_id)
    except ValueError:
        request_id = "<a KMS request id>"
    return (
        f"Secrets Manager can't {verb} the secret value: {key_arn} is disabled. (Service: AWSKMS; "
        f"Status Code: 400; Error Code: DisabledException; Request ID: {request_id}; Proxy: null)"
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _sim2real_tags(scenario: str) -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": scenario},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _kms_tags(scenario: str) -> list[dict[str, str]]:
    """KMS spells tags TagKey/TagValue. A key's only handle is a server-minted id, so the tag is the
    only thing a cleanup can match on."""
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


def _all_version_ids(sm, secret_id: str) -> set[str]:
    """Every version id, paginated."""
    ids: set[str] = set()
    token = None
    while True:
        kwargs: dict = {"SecretId": secret_id, "IncludeDeprecated": True}
        if token:
            kwargs["NextToken"] = token
        resp = sm.list_secret_version_ids(**kwargs)
        ids.update(v["VersionId"] for v in resp.get("Versions", []))
        token = resp.get("NextToken")
        if not token:
            return ids


def _enable_key(ctx, key_id: str) -> None:
    try:
        ctx.client("kms").enable_key(KeyId=key_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code != "KMSInvalidStateException":
            raise RuntimeError(f"could not re-enable CMK {key_id}: {exc}") from exc


def _schedule_key_deletion(ctx, key_id: str) -> None:
    """7 days is the AWS minimum pending window; no cleanup can shorten it, so this key is reported
    under cleanup.leftovers[] rather than claimed as cleaned."""
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
    window, so the secret would outlive the run and bill $0.40/month until reaped.
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
