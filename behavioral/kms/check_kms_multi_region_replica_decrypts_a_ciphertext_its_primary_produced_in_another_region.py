"""kms-multi-region-replica-decrypts-a-ciphertext-its-primary-produced-in-another-region."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "kms-multi-region-replica-decrypts-a-ciphertext-its-primary-produced-in-another-region"
GROUP = 'multi_region'
SERVICES = ['kms']


def _err(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call was expected to fail and it succeeded")


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check created, with the minimum 7-day pending window.

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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A multi-Region replica shares its primary's key material: ciphertext from the region-A
    primary decrypts under the region-B replica and vice versa; the encryption context still binds.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html
    """
    region_a = ctx.region
    # A multi-Region replica needs a SECOND concrete region to replicate into; region_b names one,
    # it is not a pinned resource's home region.
    region_b = "us-west-2" if region_a != "us-west-2" else "us-east-1"
    assert region_a != region_b, (region_a, region_b)
    kms_a = ctx.client("kms")
    kms_b = ctx.client("kms", region=region_b)

    primary = kms_a.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-mrkport-"),
        MultiRegion=True,
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-mrk-ciphertext-portability"}],
    )["KeyMetadata"]
    primary_arn = primary["Arn"]
    # Registered FIRST so LIFO retires it LAST, after the replica below.
    ctx.on_cleanup(lambda _a=primary_arn: _teardown_key(kms_a, _a))

    assert primary["MultiRegion"] is True, primary
    assert primary["KeyId"].startswith("mrk-"), (
        f"a multi-Region key id must carry the mrk- prefix, got {primary['KeyId']!r}"
    )
    assert primary["MultiRegionConfiguration"]["MultiRegionKeyType"] == "PRIMARY", primary
    assert primary["MultiRegionConfiguration"]["PrimaryKey"]["Region"] == region_a, primary
    assert primary["MultiRegionConfiguration"]["ReplicaKeys"] == [], (
        f"a brand-new primary must have no replicas, got "
        f"{primary['MultiRegionConfiguration']['ReplicaKeys']!r}"
    )

    plaintext = b"minted-in-region-a-opened-in-region-b"
    enc_ctx = {"tenant": "acme", "purpose": "multi-region"}

    # --- Mint the ciphertext BEFORE the replica exists, so the replica cannot have been
    # involved in producing it.
    ct_a = kms_a.encrypt(
        KeyId=primary_arn, Plaintext=plaintext, EncryptionContext=enc_ctx
    )["CiphertextBlob"]

    replica = kms_a.replicate_key(
        KeyId=primary_arn,
        ReplicaRegion=region_b,
        Description=ctx.unique_name("sim2real-behav-kms-mrkreplica-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-mrk-ciphertext-portability"}],
    )["ReplicaKeyMetadata"]
    replica_arn = replica["Arn"]
    # Registered SECOND so LIFO retires the replica FIRST.
    ctx.on_cleanup(lambda _a=replica_arn: _teardown_key(kms_b, _a))

    assert f":{region_b}:" in replica_arn, (
        f"the replica ARN must name {region_b!r}, got {replica_arn!r}"
    )
    assert replica["KeyId"] == primary["KeyId"], (
        f"a replica must share the primary's key id — only the region differs; primary "
        f"{primary['KeyId']!r} replica {replica['KeyId']!r}"
    )

    # Replica creation is asynchronous (Creating -> Enabled) and the region-B endpoint may not
    # resolve it at all for the first few seconds.
    replica_meta = _poll_until(
        lambda: _describe_or_none(kms_b, replica_arn),
        lambda m: m is not None and m["KeyState"] == "Enabled",
        timeout_s=180,
        what=f"the replica {replica_arn} to reach Enabled at the {region_b} endpoint",
    )
    assert replica_meta["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA", (
        replica_meta
    )
    assert replica_meta["MultiRegionConfiguration"]["PrimaryKey"]["Arn"] == primary_arn, (
        f"the replica must point back at its primary {primary_arn!r}: {replica_meta!r}"
    )

    # --- THE claim: region-A bytes open at the region-B endpoint. No transformation, no
    # region-A call.
    dec_b = kms_b.decrypt(
        CiphertextBlob=ct_a, KeyId=replica_arn, EncryptionContext=enc_ctx
    )
    assert dec_b["Plaintext"] == plaintext, (
        f"the replica in {region_b} could not open a ciphertext its primary produced in "
        f"{region_a} — replicas must share key material"
    )
    assert dec_b["KeyId"] == replica_arn, (
        f"the Decrypt must be attributed to the region-B replica, got {dec_b['KeyId']!r}"
    )

    # --- The reverse direction must hold too, or the sharing is one-way and not sharing.
    ct_b = kms_b.encrypt(
        KeyId=replica_arn, Plaintext=plaintext, EncryptionContext=enc_ctx
    )["CiphertextBlob"]
    assert ct_b != ct_a, "two Encrypts must not be byte-identical (fresh IV)"
    dec_a = kms_a.decrypt(CiphertextBlob=ct_b, KeyId=primary_arn, EncryptionContext=enc_ctx)
    assert dec_a["Plaintext"] == plaintext, (
        f"the primary in {region_a} could not open a ciphertext its replica produced in "
        f"{region_b} — the sharing must be symmetric"
    )
    assert dec_a["KeyId"] == primary_arn, dec_a["KeyId"]

    # --- The AAD binding is not weakened by crossing a region boundary.
    code, message = _err(lambda: kms_b.decrypt(CiphertextBlob=ct_a, KeyId=replica_arn))
    assert code == "InvalidCiphertextException", (
        f"the encryption context must still bind at the {region_b} endpoint, got {code!r}"
    )
    assert message == "", f"expected an empty InvalidCiphertextException message, got {message!r}"

    # --- Invariant: the primary now knows about its replica, and neither key moved.
    primary_after = _poll_until(
        lambda: kms_a.describe_key(KeyId=primary_arn)["KeyMetadata"],
        lambda m: m["MultiRegionConfiguration"]["ReplicaKeys"] != [],
        timeout_s=120,
        what="the primary to list its replica",
    )
    replica_regions = {
        r["Region"] for r in primary_after["MultiRegionConfiguration"]["ReplicaKeys"]
    }
    assert replica_regions == {region_b}, (
        f"the primary must list exactly one replica, in {region_b!r}, got {replica_regions!r}"
    )
    assert primary_after["KeyState"] == "Enabled", primary_after["KeyState"]
    assert primary_after["Arn"] == primary_arn, primary_after["Arn"]

    # --- Replicating to a region that already holds a replica is refused, which is what makes
    # "one replica per region" an invariant rather than a coincidence.
    dup, dup_message = _err(lambda: kms_a.replicate_key(KeyId=primary_arn, ReplicaRegion=region_b))
    assert dup == "AlreadyExistsException", (
        f"a second replica in {region_b!r} must be refused with AlreadyExistsException, got "
        f"{dup!r}"
    )
    assert dup_message == "You can create only one replica of each primary key in each AWS Region.", (
        dup_message
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
