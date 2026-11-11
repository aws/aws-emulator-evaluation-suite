"""create-partnership-nonexistent-profile-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-partnership-nonexistent-profile-rejected"
GROUP = "overly-permissive"
SERVICES = ["b2bi"]


def _error(fn) -> tuple[str, str]:
    """Call fn(), which AWS refuses; return the ClientError's (code, message). An unexpected
    success raises, so a target that accepts the call fails loudly instead of mismatching."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _list_all_partnerships(ctx) -> list:
    b2bi = ctx.client("b2bi")
    partnerships = []
    token = None
    while True:
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        page = b2bi.list_partnerships(**kwargs)
        partnerships.extend(page.get("partnerships", []))
        token = page.get("nextToken")
        if not token:
            break
    return partnerships


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
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePartnership referencing a profileId that does not exist is rejected with
    ResourceNotFoundException and creates no partnership at all; the same request with a
    real profileId succeeds (positive control)."""
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
        tags=[{"Key": "sim2real", "Value": CHECK}],
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
    capability = b2bi.create_capability(
        name=cap_name,
        type="edi",
        configuration=configuration,
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    capability_id = capability["capabilityId"]
    ctx.on_cleanup(lambda: b2bi.delete_capability(capabilityId=capability_id))

    bogus_profile_id = "nonexistent-profile-" + ctx.unique_name("x").replace("-", "")[:12]
    partner_name = ctx.unique_name("sim2real-b2bi-partner-")

    code, message = _error(
        lambda: b2bi.create_partnership(
            profileId=bogus_profile_id,
            name=partner_name,
            email="trading-partner@example.com",
            capabilities=[capability_id],
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent profileId, got {code}"
    )
    expected = f"Profile with profileId {bogus_profile_id} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no partnership was created behind the rejected call. The rejected call
    # referenced no real profile, so the only independent read that can catch a stray
    # partnership is an account-wide list, not one scoped to an unrelated profile.
    listed = _list_all_partnerships(ctx)
    assert not any(p["name"] == partner_name for p in listed), (
        "the rejected create_partnership call must not have left a partnership behind, "
        f"but a partnership named {partner_name!r} exists"
    )

    # Positive control: the identical request with a real profileId succeeds.
    real_profile_name = ctx.unique_name("sim2real-b2bi-profile-")
    real_profile = b2bi.create_profile(
        name=real_profile_name,
        phone="+14155550100",
        businessName=f"{real_profile_name}-biz",
        logging="DISABLED",
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    real_profile_id = real_profile["profileId"]
    ctx.on_cleanup(lambda: b2bi.delete_profile(profileId=real_profile_id))

    created = b2bi.create_partnership(
        profileId=real_profile_id,
        name=partner_name,
        email="trading-partner@example.com",
        capabilities=[capability_id],
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    partnership_id = created["partnershipId"]
    ctx.on_cleanup(lambda: b2bi.delete_partnership(partnershipId=partnership_id))
    assert created["profileId"] == real_profile_id, (
        f"expected the positive control's response to reference profileId {real_profile_id!r}, "
        f"got {created['profileId']!r}"
    )

    # Terminal assertion: an independent read (GetPartnership), not the mutating call's own
    # response, is what confirms the positive control actually took effect at the destination.
    fetched = b2bi.get_partnership(partnershipId=partnership_id)
    assert fetched["profileId"] == real_profile_id and fetched["name"] == partner_name, (
        f"expected GetPartnership({partnership_id!r}) to show profileId={real_profile_id!r} "
        f"name={partner_name!r}, got profileId={fetched['profileId']!r} name={fetched['name']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
