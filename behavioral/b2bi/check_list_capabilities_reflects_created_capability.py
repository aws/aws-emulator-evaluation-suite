"""list-capabilities-reflects-created-capability."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-capabilities-reflects-created-capability"
GROUP = "list"
SERVICES = ["b2bi"]


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A capability created via CreateCapability shows up, with the correct name and
    type, when the account's full capability list is paged through with ListCapabilities."""
    b2bi = ctx.client("b2bi")
    bucket = _create_bucket_for_b2bi(ctx)

    tr_name = ctx.unique_name("sim2real-b2bi-tr-")
    transformer = b2bi.create_transformer(
        name=tr_name,
        inputConversion={
            "fromFormat": "X12",
            "formatOptions": {"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        },
        mapping={"templateLanguage": "JSONATA", "template": "$"},
        tags=[{"Key": "sim2real-created-with", "Value": "list-capabilities-reflects-created-capability"}],
    )
    transformer_id = transformer["transformerId"]
    ctx.on_cleanup(lambda: b2bi.delete_transformer(transformerId=transformer_id))
    # Transformers are created Inactive; a capability can only reference an active one.
    b2bi.update_transformer(transformerId=transformer_id, status="active")

    cap_name = ctx.unique_name("sim2real-b2bi-cap-")
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
        name=cap_name,
        type="edi",
        configuration=configuration,
        tags=[{"Key": "sim2real-created-with", "Value": "list-capabilities-reflects-created-capability"}],
    )
    capability_id = created["capabilityId"]
    ctx.on_cleanup(lambda: b2bi.delete_capability(capabilityId=capability_id))

    found = None
    next_token = None
    for _ in range(50):
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        page = b2bi.list_capabilities(**kwargs)
        for cap in page["capabilities"]:
            if cap["capabilityId"] == capability_id:
                found = cap
        next_token = page.get("nextToken")
        if found is not None or not next_token:
            break

    assert found is not None, f"capability {capability_id} not found via ListCapabilities"
    assert found["name"] == cap_name, f"expected name {cap_name!r}, got {found['name']!r}"
    assert found["type"] == "edi", f"expected type 'edi', got {found['type']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
