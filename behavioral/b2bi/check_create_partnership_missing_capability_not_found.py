"""create-partnership-missing-capability-not-found."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "create-partnership-missing-capability-not-found"
GROUP = "error-semantics"
SERVICES = ["b2bi"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePartnership rejects a reference to a nonexistent capability id with
    ResourceNotFoundException and creates nothing, while the same profile can still form a
    partnership against a real capability (positive control)."""
    b2bi = ctx.client("b2bi")
    profile_id = _create_profile(ctx)

    before = _list_partnership_ids_for_profile(ctx, profile_id)
    assert before == set(), f"expected a freshly created profile to have no partnerships, got {before!r}"

    bogus_capability_id = "cap-doesnotexist0000000000"
    code, message = _error(
        lambda: b2bi.create_partnership(
            profileId=profile_id,
            name=ctx.unique_name("sim2real-b2bi-partner-"),
            email="partner@example.com",
            capabilities=[bogus_capability_id],
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Capability ID {bogus_capability_id} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = _list_partnership_ids_for_profile(ctx, profile_id)
    assert after == set(), "no partnership should have been created for the rejected request"

    # Positive control: a real capability lets partnership creation succeed for this profile.
    bucket = _create_bucket(ctx)
    transformer_id = _create_transformer(ctx)
    capability_id = b2bi.create_capability(
        name=ctx.unique_name("sim2real-b2bi-cap-"),
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
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )["capabilityId"]
    ctx.on_cleanup(lambda: b2bi.delete_capability(capabilityId=capability_id))

    partnership = b2bi.create_partnership(
        profileId=profile_id,
        name=ctx.unique_name("sim2real-b2bi-partner-"),
        email="partner@example.com",
        capabilities=[capability_id],
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    partnership_id = partnership["partnershipId"]
    ctx.on_cleanup(lambda: b2bi.delete_partnership(partnershipId=partnership_id))

    after_positive = _list_partnership_ids_for_profile(ctx, profile_id)
    assert after_positive == {partnership_id}, (
        f"expected the partnership created against a real capability to be listed, got {after_positive!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(), which AWS refuses; return the ClientError's (code, message). An unexpected
    success raises, so a target that accepts the call fails loudly instead of mismatching."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


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


def _list_partnership_ids_for_profile(ctx: Any, profile_id: str) -> set:
    b2bi = ctx.client("b2bi")
    ids = set()
    token = None
    while True:
        kwargs = {"profileId": profile_id}
        if token:
            kwargs["nextToken"] = token
        page = b2bi.list_partnerships(**kwargs)
        for p in page.get("partnerships", []):
            ids.add(p["partnershipId"])
        token = page.get("nextToken")
        if not token:
            break
    return ids


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
