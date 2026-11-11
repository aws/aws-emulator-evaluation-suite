"""key-arn-from-another-region-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "key-arn-from-another-region-not-found"
GROUP = "cross-region-key-resolution"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Encrypt in region B with a single-Region key ARN from region A is NotFoundException, while
    the ARN still works in region A and a multi-Region replica's own ARN encrypts in region B.
    """
    region_a = ctx.region
    region_b = "us-east-1" if region_a != "us-east-1" else "us-west-2"
    assert region_a != region_b, (region_a, region_b)

    kms_a = ctx.client("kms")
    kms_b = ctx.client("kms", region=region_b)
    tag = [{"TagKey": "sim2real", "TagValue": "kms-key-arn-from-another-region-not-found"}]

    # A single-Region key that exists ONLY in region A.
    key_a = kms_a.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-xregion-single-"),
        KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT", Tags=tag,
    )["KeyMetadata"]
    key_a_arn = key_a["Arn"]
    ctx.on_cleanup(lambda _a=key_a_arn: _teardown_key(kms_a, _a))
    assert key_a.get("MultiRegion") is False, (
        f"the control key must be single-Region, got MultiRegion={key_a.get('MultiRegion')!r}"
    )

    err = _error(lambda: kms_b.encrypt(KeyId=key_a_arn, Plaintext=b"cross-region-probe"))
    # The refusal names the region the ARN belongs to, not the key: region B rejects the ARN itself.
    expected = ("NotFoundException", f"Invalid arn {region_a}")
    assert err == expected, (
        f"Encrypt at {region_b} with a {region_a}-only key ARN must be {expected!r}, got {err!r}"
    )

    # The same ARN still works in the region it belongs to.
    ct_a = kms_a.encrypt(KeyId=key_a_arn, Plaintext=b"cross-region-probe")["CiphertextBlob"]
    assert kms_a.decrypt(CiphertextBlob=ct_a, KeyId=key_a_arn)["Plaintext"] == b"cross-region-probe", (
        "positive control: the region-A key must still encrypt/decrypt normally at region A"
    )

    # The rejected cross-region Encrypt did not disturb the key's state.
    key_a_after = kms_a.describe_key(KeyId=key_a_arn)["KeyMetadata"]
    assert key_a_after["KeyState"] == "Enabled" and key_a_after["Enabled"] is True, key_a_after

    # A replica's own ARN is a real key in region B, so the refusal above is about this key's
    # absence there, not a blanket refusal of cross-region ARNs.
    mrk = kms_a.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-xregion-mrk-"),
        MultiRegion=True, KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT", Tags=tag,
    )["KeyMetadata"]
    mrk_arn = mrk["Arn"]
    ctx.on_cleanup(lambda _a=mrk_arn: _teardown_key(kms_a, _a))  # LIFO: after its replica below

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

    replica_encrypt = kms_b.encrypt(KeyId=replica_arn, Plaintext=b"cross-region-probe")
    assert replica_encrypt["KeyId"] == replica_arn, (
        f"positive control: a multi-Region replica's own ARN must Encrypt successfully at its "
        f"own ({region_b}) endpoint -- got KeyId {replica_encrypt['KeyId']!r}"
    )


def _error(fn):
    """Return (Error.Code, Error.Message) if fn() raises ClientError; raise if fn() succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("the call was expected to fail and it succeeded")


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7 days is the AWS minimum window).

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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
