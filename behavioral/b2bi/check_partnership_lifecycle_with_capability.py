"""partnership-lifecycle-with-capability."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partnership-lifecycle-with-capability"
GROUP = "lifecycle"
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


def _create_transformer_legacy(ctx) -> str:
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


def _delete_partnership_if_present(b2bi, partnership_id: str) -> None:
    try:
        b2bi.delete_partnership(partnershipId=partnership_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePartnership tying a profile to a capability round-trips through GetPartnership
    and appears in ListPartnerships; deleting it removes it from the listing."""
    b2bi = ctx.client("b2bi")
    bucket = _create_bucket_for_b2bi(ctx)
    transformer_id = _create_transformer_legacy(ctx)
    capability_id = _create_capability(ctx, transformer_id, bucket)
    profile_id = _create_profile(ctx)

    name = ctx.unique_name("sim2real-b2bi-partner-")
    created = b2bi.create_partnership(
        profileId=profile_id,
        name=name,
        email="trading-partner@example.com",
        capabilities=[capability_id],
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    partnership_id = created["partnershipId"]
    ctx.on_cleanup(lambda: _delete_partnership_if_present(b2bi, partnership_id))

    assert created["profileId"] == profile_id, (
        f"expected CreatePartnership to echo profileId={profile_id!r}, got {created['profileId']!r}"
    )
    assert created["capabilities"] == [capability_id], (
        f"expected CreatePartnership capabilities=[{capability_id!r}], got {created['capabilities']!r}"
    )
    assert created["tradingPartnerId"], "expected a system-generated tradingPartnerId"

    fetched = b2bi.get_partnership(partnershipId=partnership_id)
    assert fetched["name"] == name, f"expected GetPartnership name={name!r}, got {fetched['name']!r}"
    assert fetched["capabilities"] == [capability_id], (
        f"expected GetPartnership capabilities=[{capability_id!r}], got {fetched['capabilities']!r}"
    )

    listed = b2bi.list_partnerships(profileId=profile_id, maxResults=100)["partnerships"]
    listed_ids = {p["partnershipId"] for p in listed}
    assert partnership_id in listed_ids, (
        f"expected {partnership_id!r} in ListPartnerships(profileId={profile_id!r}), got {listed_ids!r}"
    )

    b2bi.delete_partnership(partnershipId=partnership_id)
    listed_after = b2bi.list_partnerships(profileId=profile_id, maxResults=100)["partnerships"]
    listed_after_ids = {p["partnershipId"] for p in listed_after}
    assert partnership_id not in listed_after_ids, (
        f"expected {partnership_id!r} absent from ListPartnerships after DeletePartnership, "
        f"got {listed_after_ids!r}"
    )

    try:
        b2bi.get_partnership(partnershipId=partnership_id)
        raise AssertionError("expected GetPartnership on a deleted partnership to raise")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException reading a deleted partnership, got {code!r}"
        )
        message = err.response["Error"].get("Message", "")
        expected = f"Partnership with partnershipId {partnership_id} not found."
        assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
