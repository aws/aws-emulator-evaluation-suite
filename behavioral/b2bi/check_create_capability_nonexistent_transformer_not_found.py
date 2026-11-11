"""create-capability-nonexistent-transformer-not-found."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "create-capability-nonexistent-transformer-not-found"
GROUP = "error-semantics"
SERVICES = ["b2bi"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCapability rejects an edi configuration referencing a transformerId that does
    not exist with ResourceNotFoundException and creates nothing, while the identical request
    against a real transformer succeeds (positive control)."""
    b2bi = ctx.client("b2bi")
    bucket = _create_bucket(ctx)

    bogus_transformer_id = "xfmr-doesnotexist00000000"
    cap_name = ctx.unique_name("sim2real-b2bi-cap-")
    code, message = _error(
        lambda: b2bi.create_capability(
            name=cap_name,
            type="edi",
            configuration={
                "edi": {
                    "type": {"x12Details": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
                    "inputLocation": {"bucketName": bucket, "key": "in/"},
                    "outputLocation": {"bucketName": bucket, "key": "out/"},
                    "transformerId": bogus_transformer_id,
                    "capabilityDirection": "INBOUND",
                }
            },
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Transformer with transformerId {bogus_transformer_id} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert not _capability_name_exists(ctx, cap_name), "the rejected request must not have created a capability"

    # Positive control: the identical request against a real transformer succeeds.
    transformer_id = _create_transformer(ctx)
    ok = b2bi.create_capability(
        name=cap_name,
        type="edi",
        configuration={
            "edi": {
                "type": {"x12Details": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
                "inputLocation": {"bucketName": bucket, "key": "in/"},
                "outputLocation": {"bucketName": bucket, "key": "out/"},
                "transformerId": transformer_id,
                "capabilityDirection": "INBOUND",
            }
        },
        tags=[{"Key": "sim2real", "Value": "true"}],
    )
    capability_id = ok["capabilityId"]
    ctx.on_cleanup(lambda: b2bi.delete_capability(capabilityId=capability_id))
    assert _capability_name_exists(ctx, cap_name)


def _error(fn) -> tuple[str, str]:
    """Call fn(), which AWS refuses; return the ClientError's (code, message). An unexpected
    success raises, so a target that accepts the call fails loudly instead of mismatching."""
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
        tags=[{"Key": "sim2real", "Value": "true"}],
    )
    transformer_id = resp["transformerId"]
    ctx.on_cleanup(lambda: b2bi.delete_transformer(transformerId=transformer_id))
    # Transformers are created Inactive; a capability can only reference an active one.
    b2bi.update_transformer(transformerId=transformer_id, status="active")
    return transformer_id


def _capability_name_exists(ctx: Any, name: str) -> bool:
    b2bi = ctx.client("b2bi")
    token = None
    while True:
        kwargs = {}
        if token:
            kwargs["nextToken"] = token
        page = b2bi.list_capabilities(**kwargs)
        if any(c["name"] == name for c in page.get("capabilities", [])):
            return True
        token = page.get("nextToken")
        if not token:
            return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
