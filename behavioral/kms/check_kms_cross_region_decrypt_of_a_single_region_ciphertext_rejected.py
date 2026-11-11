"""kms-cross-region-decrypt-of-a-single-region-ciphertext-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "kms-cross-region-decrypt-of-a-single-region-ciphertext-rejected"
GROUP = 'multi_region'
SERVICES = ['kms']

ERR_CROSS_REGION = "AccessDeniedException"


def _client_error(fn):
    """Return the botocore Error if fn() raises ClientError; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("the call was expected to fail and it succeeded")


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion (minimum 7-day window) of a CMK this check minted.

    The ARN guard keeps this teardown off AWS-managed keys and aliases.
    """
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    for attempt in range(4):
        try:
            kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "KMSInvalidStateException":
                return  # already PendingDeletion
            if code not in ("ThrottlingException", "KMSInternalException") or attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))


def _poll_until(fn, predicate, *, timeout_s: float, interval_s: float = 3.0, what: str = ""):
    """Poll fn() until predicate(value) is true. Returns the value, or raises AssertionError."""
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last saw {last!r}")


def _describe_or_none(kms, key_arn: str):
    """describe_key, treating NotFoundException as 'the replica has not appeared yet'."""
    try:
        return kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NotFoundException":
            return None
        raise


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Region-A single-Region ciphertext is refused at region B with AccessDeniedException (foreign
    or local KeyId), still opens in region A, and a multi-Region replica opens its primary's bytes.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html
    """
    region_a = ctx.region
    # Any distinct region works; the pair is literal because the subject is the region boundary.
    region_b = "us-west-2" if region_a != "us-west-2" else "us-east-1"
    assert region_a != region_b, (region_a, region_b)
    kms_a = ctx.client("kms")
    kms_b = ctx.client("kms", region=region_b)

    tag = [{"TagKey": "sim2real", "TagValue": "kms-cross-region-single-region-isolation"}]

    key_a = kms_a.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-xregion-a-"),
        KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT", Tags=tag,
    )["KeyMetadata"]
    key_a_arn = key_a["Arn"]
    ctx.on_cleanup(lambda _a=key_a_arn: _teardown_key(kms_a, _a))
    assert key_a.get("MultiRegion") is False, (
        f"the region-A control key must be single-Region, got MultiRegion="
        f"{key_a.get('MultiRegion')!r}"
    )

    key_b = kms_b.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-xregion-b-"),
        KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT", Tags=tag,
    )["KeyMetadata"]
    key_b_arn = key_b["Arn"]
    ctx.on_cleanup(lambda _a=key_b_arn: _teardown_key(kms_b, _a))
    assert f":{region_b}:" in key_b_arn, key_b_arn

    mrk = kms_a.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-xregion-mrk-"),
        MultiRegion=True, KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT", Tags=tag,
    )["KeyMetadata"]
    mrk_arn = mrk["Arn"]
    ctx.on_cleanup(lambda _a=mrk_arn: _teardown_key(kms_a, _a))  # LIFO: retired after its replica

    replica_arn = kms_a.replicate_key(
        KeyId=mrk_arn, ReplicaRegion=region_b,
        Description=ctx.unique_name("sim2real-behav-kms-xregion-replica-"), Tags=tag,
    )["ReplicaKeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda _a=replica_arn: _teardown_key(kms_b, _a))
    _poll_until(
        lambda: _describe_or_none(kms_b, replica_arn),
        lambda m: m is not None and m["KeyState"] == "Enabled",
        timeout_s=180,
        what=f"the replica {replica_arn} to reach Enabled at the {region_b} endpoint",
    )

    plaintext = b"single-region-material-must-not-travel"

    ct_a = kms_a.encrypt(KeyId=key_a_arn, Plaintext=plaintext)["CiphertextBlob"]
    ct_mrk = kms_a.encrypt(KeyId=mrk_arn, Plaintext=plaintext)["CiphertextBlob"]

    # --- Negative 1: the region-A key ARN is not usable at region B. KMS refuses on authorization
    # (AccessDeniedException), not NotFoundException.
    # The refusal opens with the caller's ARN.
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    denied_message = (
        f"User: {caller_arn} is not authorized to perform: kms:Decrypt on the resource associated "
        "with this ciphertext because the resource does not exist in this Region, no resource-based "
        "policies allow access, or a resource-based policy explicitly denies access"
    )
    foreign_arn = _client_error(
        lambda: kms_b.decrypt(CiphertextBlob=ct_a, KeyId=key_a_arn)
    )
    assert foreign_arn["Code"] == ERR_CROSS_REGION, (
        f"a region-A key ARN presented to the {region_b} endpoint must be refused with "
        f"{ERR_CROSS_REGION}, got {foreign_arn!r}"
    )
    assert foreign_arn["Message"] == denied_message, (
        f"expected {denied_message!r}, got {foreign_arn['Message']!r}"
    )

    # --- Negative 2: a REAL region-B key, and the caller is authorized on it (it decrypts its
    # own ciphertext below). Only the material is foreign; still AccessDenied, not IncorrectKey.
    wrong_material = _client_error(
        lambda: kms_b.decrypt(CiphertextBlob=ct_a, KeyId=key_b_arn)
    )
    assert wrong_material["Code"] == ERR_CROSS_REGION, (
        f"region-A ciphertext bytes presented to the region-B key {key_b_arn!r} must be refused "
        f"with {ERR_CROSS_REGION}, got {wrong_material!r}"
    )
    assert wrong_material["Message"] == denied_message, (
        f"expected {denied_message!r}, got {wrong_material['Message']!r}"
    )

    # --- Effect absent: neither refusal disturbed the region-B key, and it still works. This is
    # also what proves the refusals above are not a credentials problem.
    key_b_after = kms_b.describe_key(KeyId=key_b_arn)["KeyMetadata"]
    assert key_b_after["KeyState"] == "Enabled" and key_b_after["Enabled"] is True, key_b_after
    ct_b_own = kms_b.encrypt(KeyId=key_b_arn, Plaintext=plaintext)["CiphertextBlob"]
    assert kms_b.decrypt(
        CiphertextBlob=ct_b_own, KeyId=key_b_arn
    )["Plaintext"] == plaintext, (
        f"the caller must be able to use the region-B key normally — otherwise the two refusals "
        f"above are about permissions, not about region isolation"
    )

    # --- Positive control 1: the bytes are not corrupt. They still open in their own region.
    assert kms_a.decrypt(
        CiphertextBlob=ct_a, KeyId=key_a_arn
    )["Plaintext"] == plaintext, (
        "positive control: the region-A ciphertext must still open at the region-A endpoint"
    )

    # --- Positive control 2: shared material DOES cross the boundary, so the refusals above are
    # about material, not a blanket cross-region refusal.
    dec_mrk = kms_b.decrypt(CiphertextBlob=ct_mrk, KeyId=replica_arn)
    assert dec_mrk["Plaintext"] == plaintext, (
        f"positive control: a multi-Region replica in {region_b} MUST open its primary's "
        f"{region_a} ciphertext — otherwise this check cannot tell isolation from a blanket "
        f"cross-region refusal"
    )
    assert dec_mrk["KeyId"] == replica_arn, dec_mrk["KeyId"]

    # --- And the single-Region key in region A is untouched by any of it.
    key_a_after = kms_a.describe_key(KeyId=key_a_arn)["KeyMetadata"]
    assert key_a_after["KeyState"] == "Enabled", key_a_after["KeyState"]
    assert key_a_after["Arn"] == key_a_arn, key_a_after["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
