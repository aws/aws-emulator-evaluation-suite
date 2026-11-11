"""capability-crud-with-transformer-reference."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capability-crud-with-transformer-reference"
GROUP = "lifecycle"
SERVICES = ["b2bi"]


def _error(fn) -> tuple[str, str]:
    """Call fn(), which AWS refuses; return the ClientError's (code, message). An unexpected
    success raises, so accepting a request AWS refuses fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _delete_if_present(fn) -> None:
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_bucket_for_b2bi(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-b2bi-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowB2BIAccess",
                "Effect": "Allow",
                "Principal": {"Service": "b2bi.amazonaws.com"},
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_transformer_legacy(ctx, name: str | None = None) -> str:
    b2bi = ctx.client("b2bi")
    name = name or ctx.unique_name("sim2real-b2bi-tr-")
    resp = b2bi.create_transformer(
        name=name,
        inputConversion={
            "fromFormat": "X12",
            "formatOptions": {"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        },
        mapping={"templateLanguage": "JSONATA", "template": "$"},
        tags=[{"Key": "sim2real", "Value": "true"}],
    )
    transformer_id = resp["transformerId"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: b2bi.delete_transformer(transformerId=transformer_id)))
    assert resp["status"] == "inactive", f"expected a newly created transformer to be inactive, got {resp['status']!r}"
    activated = b2bi.update_transformer(transformerId=transformer_id, status="active")
    assert activated["status"] == "active", (
        f"expected UpdateTransformer to report status active, got {activated['status']!r}"
    )
    return transformer_id


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A capability referencing a transformer round-trips through GetCapability and
    UpdateCapability; after DeleteCapability both a read and a mutation of its id return
    ResourceNotFoundException."""
    b2bi = ctx.client("b2bi")
    bucket = _create_bucket_for_b2bi(ctx)
    transformer_id = _create_transformer_legacy(ctx)

    name = ctx.unique_name("sim2real-b2bi-cap-")
    configuration = {
        "edi": {
            "type": {"x12Details": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
            "inputLocation": {"bucketName": bucket, "key": "in/"},
            "outputLocation": {"bucketName": bucket, "key": "out/"},
            "transformerId": transformer_id,
            "capabilityDirection": "INBOUND",
        }
    }
    created = b2bi.create_capability(
        name=name,
        type="edi",
        configuration=configuration,
        tags=[{"Key": "sim2real", "Value": "true"}],
    )
    capability_id = created["capabilityId"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: b2bi.delete_capability(capabilityId=capability_id)))

    assert created["configuration"]["edi"]["transformerId"] == transformer_id, (
        f"expected CreateCapability to echo transformerId {transformer_id!r}, "
        f"got {created['configuration']['edi'].get('transformerId')!r}"
    )

    fetched = b2bi.get_capability(capabilityId=capability_id)
    assert fetched["name"] == name, f"expected GetCapability name {name!r}, got {fetched['name']!r}"
    assert fetched["configuration"]["edi"]["transformerId"] == transformer_id, (
        f"expected GetCapability to report transformerId {transformer_id!r}, "
        f"got {fetched['configuration']['edi'].get('transformerId')!r}"
    )

    new_name = name + "-renamed"
    updated = b2bi.update_capability(capabilityId=capability_id, name=new_name)
    assert updated["name"] == new_name, (
        f"expected UpdateCapability to return the new name {new_name!r}, got {updated['name']!r}"
    )

    refetched = b2bi.get_capability(capabilityId=capability_id)
    assert refetched["name"] == new_name, (
        f"expected the renamed capability to persist as {new_name!r}, got {refetched['name']!r}"
    )
    assert refetched["configuration"]["edi"]["transformerId"] == transformer_id, (
        f"expected the transformer reference to survive the rename, "
        f"got {refetched['configuration']['edi'].get('transformerId')!r}"
    )

    # A deleted capability is gone and unusable: a mutation against its id is rejected,
    # and an independent read confirms it is gone.
    b2bi.delete_capability(capabilityId=capability_id)
    code, message = _error(lambda: b2bi.update_capability(capabilityId=capability_id, name="sim2real-dead"))
    assert code == "ResourceNotFoundException", (
        f"expected UpdateCapability on a deleted capability to raise ResourceNotFoundException, got {code!r}"
    )
    expected = f"Capability with capabilityId {capability_id} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    code, message = _error(lambda: b2bi.get_capability(capabilityId=capability_id))
    assert code == "ResourceNotFoundException", (
        f"expected GetCapability on a deleted capability to raise ResourceNotFoundException, got {code!r}"
    )
    expected = f"Capability ID {capability_id} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
