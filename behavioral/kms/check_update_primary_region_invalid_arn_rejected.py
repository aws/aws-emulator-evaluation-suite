"""update-primary-region-invalid-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-primary-region-invalid-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePrimaryRegion with a mangled same-account key ARN is NotFoundException "Invalid arn
    <region>", and with a real single-Region key it is UnsupportedOperationException "<arn> is not a
    multi-region key.", which leaves that key enabled and single-Region."""
    kms = ctx.client("kms")

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    # the identity of this region is irrelevant to the assertions below; only that it differs
    # from ctx.region, both inside the malformed ARN and as the PrimaryRegion argument (a
    # PrimaryRegion equal to ctx.region would exercise a different, unrelated validation path).
    other_region = "eu-west-1" if ctx.region != "eu-west-1" else "us-west-2"
    malformed_arn = f"arn:aws:kms:{other_region}:{account_id}:key/00000000-0000-0000-0000-000000000000"

    err = _error(
        lambda: kms.update_primary_region(KeyId=malformed_arn, PrimaryRegion=other_region)
    )
    assert err["Code"] == "NotFoundException", f"expected NotFoundException, got {err!r}"
    assert err["Message"] == f"Invalid arn {other_region}", err

    # positive control: a well-formed KeyId for a real (non-multi-Region) key reaches the
    # business-logic check instead, and is rejected with a *different*, deterministic code --
    # proving the malformed-ARN rejection above is a distinct, earlier validation stage.
    key_id, key_arn = _create_symmetric_key(ctx)
    err2 = _error(
        lambda: kms.update_primary_region(KeyId=key_id, PrimaryRegion=other_region)
    )
    assert err2["Code"] == "UnsupportedOperationException", (
        f"expected UnsupportedOperationException, got {err2!r}"
    )
    assert err2["Message"] == f"{key_arn} is not a multi-region key.", err2

    # effect-absent: the rejected call left the real key's (single-region) configuration alone.
    unaffected = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert unaffected["MultiRegion"] is False, unaffected
    assert unaffected["KeyState"] == "Enabled", unaffected


def _error(fn):
    """The error (Code and Message) of a call real AWS refuses; an unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        e = err.response["Error"]
        return {"Code": e.get("Code"), "Message": e.get("Message")}
    raise AssertionError(f"expected rejection but the call succeeded: {result!r}")


def _create_symmetric_key(ctx):
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-behavioral"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms, key_id))
    return key_id, key["Arn"]


def _safe_schedule_delete(client, key_id):
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
