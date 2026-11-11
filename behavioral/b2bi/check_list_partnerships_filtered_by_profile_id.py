"""list-partnerships-filtered-by-profile-id."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-partnerships-filtered-by-profile-id"
GROUP = "list"
SERVICES = ["b2bi"]


def _create_bucket_for_b2bi(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-b2bi-").lower().replace("_", "-")
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint;
    # this branches on ctx.region's value, not a pinned target region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
        tags=[{"Key": "sim2real", "Value": CHECK}],
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
        name=name, type="edi", configuration=configuration,
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    capability_id = resp["capabilityId"]
    ctx.on_cleanup(lambda: b2bi.delete_capability(capabilityId=capability_id))
    return capability_id


def _create_profile(ctx) -> str:
    b2bi = ctx.client("b2bi")
    name = ctx.unique_name("sim2real-b2bi-profile-")
    resp = b2bi.create_profile(
        name=name, phone="+14155550100", businessName=f"{name}-biz", logging="DISABLED",
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    profile_id = resp["profileId"]
    ctx.on_cleanup(lambda: b2bi.delete_profile(profileId=profile_id))
    return profile_id


def _create_partnership(ctx, profile_id: str, capability_id: str) -> str:
    b2bi = ctx.client("b2bi")
    name = ctx.unique_name("sim2real-b2bi-partner-")
    resp = b2bi.create_partnership(
        profileId=profile_id,
        name=name,
        email="trading-partner@example.com",
        capabilities=[capability_id],
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    partnership_id = resp["partnershipId"]
    ctx.on_cleanup(lambda: b2bi.delete_partnership(partnershipId=partnership_id))
    return partnership_id


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPartnerships filtered by profileId returns only that profile's partnerships,
    not partnerships belonging to a different profile that happen to share a capability."""
    b2bi = ctx.client("b2bi")
    bucket = _create_bucket_for_b2bi(ctx)
    transformer_id = _create_transformer(ctx)
    capability_id = _create_capability(ctx, transformer_id, bucket)

    profile_a = _create_profile(ctx)
    profile_b = _create_profile(ctx)
    partnership_a = _create_partnership(ctx, profile_a, capability_id)
    partnership_b = _create_partnership(ctx, profile_b, capability_id)

    listed_a = b2bi.list_partnerships(profileId=profile_a, maxResults=100)["partnerships"]
    ids_a = {p["partnershipId"] for p in listed_a}
    assert partnership_a in ids_a, (
        f"expected {partnership_a} in ListPartnerships(profileId={profile_a}), got {ids_a}"
    )
    assert partnership_b not in ids_a, (
        f"ListPartnerships(profileId={profile_a}) must not return {profile_b}'s partnership"
    )
    other_profile_ids = {p["profileId"] for p in listed_a} - {profile_a}
    assert not other_profile_ids, (
        f"ListPartnerships(profileId={profile_a}) returned foreign profileId(s) {other_profile_ids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
