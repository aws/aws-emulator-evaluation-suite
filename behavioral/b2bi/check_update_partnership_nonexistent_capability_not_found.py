"""update-partnership-nonexistent-capability-not-found."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "update-partnership-nonexistent-capability-not-found"
GROUP = "error-semantics"
SERVICES = ["b2bi"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePartnership adding a nonexistent capability id fails with ResourceNotFoundException and
    leaves the capabilities list unchanged; replacing it with a real capability succeeds."""
    b2bi = ctx.client("b2bi")
    bucket = _create_bucket(ctx)
    transformer_id = _create_transformer(ctx)

    capability_a = _create_capability(ctx, transformer_id, bucket, "in-a/", "out-a/")
    capability_b = _create_capability(ctx, transformer_id, bucket, "in-b/", "out-b/")

    profile_id = _create_profile(ctx)
    partnership = b2bi.create_partnership(
        profileId=profile_id,
        name=ctx.unique_name("sim2real-b2bi-partner-"),
        email="partner@example.com",
        capabilities=[capability_a],
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    partnership_id = partnership["partnershipId"]
    ctx.on_cleanup(lambda: b2bi.delete_partnership(partnershipId=partnership_id))

    bogus_capability_id = "cap-doesnotexist0000000000"
    code, message = _error(
        lambda: b2bi.update_partnership(
            partnershipId=partnership_id, capabilities=[capability_a, bogus_capability_id]
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Capability ID {bogus_capability_id} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = b2bi.get_partnership(partnershipId=partnership_id)
    assert unchanged["capabilities"] == [capability_a], (
        f"the rejected update must not have changed the capabilities list, got {unchanged['capabilities']!r}"
    )

    # Positive control: replacing it with a different real capability succeeds; two capabilities
    # of the same edi type cannot coexist in one partnership ("duplicated capability type").
    updated = b2bi.update_partnership(partnershipId=partnership_id, capabilities=[capability_b])
    assert updated["capabilities"] == [capability_b]

    fetched = b2bi.get_partnership(partnershipId=partnership_id)
    assert fetched["capabilities"] == [capability_b], (
        f"expected an independent read to reflect the accepted update, got {fetched['capabilities']!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(), which AWS refuses; return the ClientError's (code, message). An unexpected
    success raises, so accepting a request AWS refuses fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-b2bi-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_transformer(ctx: Any) -> str:
    b2bi = ctx.client("b2bi")
    resp = b2bi.create_transformer(
        name=ctx.unique_name("sim2real-b2bi-xfmr-"),
        inputConversion={
            "fromFormat": "X12",
            "formatOptions": {"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        },
        mapping={"templateLanguage": "JSONATA", "template": "$"},
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    transformer_id = resp["transformerId"]
    ctx.on_cleanup(lambda: b2bi.delete_transformer(transformerId=transformer_id))
    # Transformers are created Inactive; a capability can only reference an active one.
    b2bi.update_transformer(transformerId=transformer_id, status="active")
    return transformer_id


def _create_capability(ctx: Any, transformer_id: str, bucket: str, in_key: str, out_key: str) -> str:
    b2bi = ctx.client("b2bi")
    resp = b2bi.create_capability(
        name=ctx.unique_name("sim2real-b2bi-cap-"),
        type="edi",
        configuration={
            "edi": {
                "type": {"x12Details": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
                "inputLocation": {"bucketName": bucket, "key": in_key},
                "outputLocation": {"bucketName": bucket, "key": out_key},
                "transformerId": transformer_id,
                "capabilityDirection": "INBOUND",
            }
        },
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    capability_id = resp["capabilityId"]
    ctx.on_cleanup(lambda: b2bi.delete_capability(capabilityId=capability_id))
    return capability_id


def _create_profile(ctx: Any) -> str:
    b2bi = ctx.client("b2bi")
    resp = b2bi.create_profile(
        name=ctx.unique_name("sim2real-b2bi-profile-"),
        phone="+15555550100",
        businessName=ctx.unique_name("sim2real-b2bi-biz-"),
        logging="DISABLED",
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    profile_id = resp["profileId"]
    ctx.on_cleanup(lambda: b2bi.delete_profile(profileId=profile_id))
    return profile_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
