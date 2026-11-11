"""update-partnership-capabilities-list-replace."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-partnership-capabilities-list-replace"
GROUP = "lifecycle"
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


def _create_transformer(ctx) -> str:
    b2bi = ctx.client("b2bi")
    name = ctx.unique_name("sim2real-b2bi-tr-")
    resp = b2bi.create_transformer(
        name=name,
        inputConversion={
            "fromFormat": "X12",
            "formatOptions": {"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        },
        mapping={"templateLanguage": "JSONATA", "template": "$"},
        tags=[{"Key": "sim2real-owner", "Value": "behavioral"}],
    )
    transformer_id = resp["transformerId"]
    ctx.on_cleanup(lambda: b2bi.delete_transformer(transformerId=transformer_id))
    # Transformers are created Inactive; a capability can only reference an active one.
    b2bi.update_transformer(transformerId=transformer_id, status="active")
    return transformer_id


def _create_capability(ctx, transformer_id: str, bucket: str) -> str:
    b2bi = ctx.client("b2bi")
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
    resp = b2bi.create_capability(
        name=name,
        type="edi",
        configuration=configuration,
        tags=[{"Key": "sim2real-owner", "Value": "behavioral"}],
    )
    capability_id = resp["capabilityId"]
    ctx.on_cleanup(lambda: b2bi.delete_capability(capabilityId=capability_id))
    return capability_id


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePartnership's capabilities list REPLACES the previous set rather than
    appending to it: swapping capability A for capability B leaves the partnership with
    only B."""
    b2bi = ctx.client("b2bi")
    bucket = _create_bucket_for_b2bi(ctx)
    transformer_a = _create_transformer(ctx)
    transformer_b = _create_transformer(ctx)
    capability_a = _create_capability(ctx, transformer_a, bucket)
    capability_b = _create_capability(ctx, transformer_b, bucket)

    profile_name = ctx.unique_name("sim2real-b2bi-profile-")
    profile = b2bi.create_profile(
        name=profile_name,
        phone="+14155550100",
        businessName=f"{profile_name}-biz",
        logging="DISABLED",
        tags=[{"Key": "sim2real-owner", "Value": "behavioral"}],
    )
    profile_id = profile["profileId"]
    ctx.on_cleanup(lambda: b2bi.delete_profile(profileId=profile_id))

    partner_name = ctx.unique_name("sim2real-b2bi-partner-")
    created = b2bi.create_partnership(
        profileId=profile_id,
        name=partner_name,
        email="trading-partner@example.com",
        capabilities=[capability_a],
        tags=[{"Key": "sim2real-owner", "Value": "behavioral"}],
    )
    partnership_id = created["partnershipId"]
    ctx.on_cleanup(lambda: b2bi.delete_partnership(partnershipId=partnership_id))
    assert created["capabilities"] == [capability_a], (
        f"expected CreatePartnership's own response to echo [{capability_a}], got {created['capabilities']}"
    )

    updated = b2bi.update_partnership(partnershipId=partnership_id, capabilities=[capability_b])
    assert updated["capabilities"] == [capability_b], (
        f"expected the capabilities list to be replaced with [{capability_b}], got {updated['capabilities']}"
    )

    fetched = b2bi.get_partnership(partnershipId=partnership_id)
    assert fetched["capabilities"] == [capability_b], (
        f"GetPartnership (independent read): expected [{capability_b}], got {fetched['capabilities']}"
    )
    assert capability_a not in fetched["capabilities"], (
        f"expected {capability_a} to have been replaced, not appended; got {fetched['capabilities']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
