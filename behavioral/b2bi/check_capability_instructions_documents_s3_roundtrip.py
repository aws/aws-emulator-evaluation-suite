"""capability-instructions-documents-s3-roundtrip."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "capability-instructions-documents-s3-roundtrip"
GROUP = "state"
SERVICES = ["b2bi"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCapability's instructionsDocuments field genuinely persists the given S3
    locations and returns them unchanged from GetCapability -- not silently dropped."""
    b2bi = ctx.client("b2bi")
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    doc_key = "instructions/how-to-trade.pdf"
    s3.put_object(Bucket=bucket, Key=doc_key, Body=b"instructions for this trading capability")

    transformer_id = _create_transformer(ctx)

    resp = b2bi.create_capability(
        name=ctx.unique_name("sim2real-b2bi-cap-"),
        type="edi",
        instructionsDocuments=[{"bucketName": bucket, "key": doc_key}],
        tags=[{"Key": "sim2real", "Value": "capability-instructions-documents-s3-roundtrip"}],
        configuration={
            "edi": {
                "type": {"x12Details": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
                "inputLocation": {"bucketName": bucket, "key": "in/"},
                "outputLocation": {"bucketName": bucket, "key": "out/"},
                "transformerId": transformer_id,
                "capabilityDirection": "INBOUND",
            }
        },
    )
    capability_id = resp["capabilityId"]
    ctx.on_cleanup(lambda: b2bi.delete_capability(capabilityId=capability_id))

    assert resp["instructionsDocuments"] == [{"bucketName": bucket, "key": doc_key}], (
        f"expected CreateCapability to echo instructionsDocuments, got {resp.get('instructionsDocuments')!r}"
    )

    described = b2bi.get_capability(capabilityId=capability_id)
    assert described["instructionsDocuments"] == [{"bucketName": bucket, "key": doc_key}], (
        f"expected instructionsDocuments to round-trip, got {described.get('instructionsDocuments')!r}"
    )


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-b2bi-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "capability-instructions-documents-s3-roundtrip"}]})

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
        tags=[{"Key": "sim2real", "Value": "capability-instructions-documents-s3-roundtrip"}],
    )
    transformer_id = resp["transformerId"]
    ctx.on_cleanup(lambda: b2bi.delete_transformer(transformerId=transformer_id))
    # Transformers are created Inactive; a capability can only reference an active one.
    b2bi.update_transformer(transformerId=transformer_id, status="active")
    return transformer_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
