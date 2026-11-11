"""delete-dependency-order-enforced-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-dependency-order-enforced-rejected"
GROUP = "overly-permissive"
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
        # us-east-1 is the one region where S3 rejects an explicit LocationConstraint.
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a transformer, capability or profile still referenced by a dependent fails with
    ConflictException and leaves it intact; each delete succeeds once its dependent is removed."""
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
    )
    transformer_id = transformer["transformerId"]
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
    capability = b2bi.create_capability(name=cap_name, type="edi", configuration=configuration)
    capability_id = capability["capabilityId"]

    profile_name = ctx.unique_name("sim2real-b2bi-profile-")
    profile = b2bi.create_profile(
        name=profile_name, phone="+14155550100", businessName=f"{profile_name}-biz", logging="DISABLED"
    )
    profile_id = profile["profileId"]

    partner_name = ctx.unique_name("sim2real-b2bi-partner-")
    partnership = b2bi.create_partnership(
        profileId=profile_id,
        name=partner_name,
        email="trading-partner@example.com",
        capabilities=[capability_id],
    )
    partnership_id = partnership["partnershipId"]

    # Safety-net cleanup in dependency order, in case an assertion below fails before the
    # positive-control deletion sequence runs.
    ctx.on_cleanup(lambda: _delete_if_present(lambda: b2bi.delete_profile(profileId=profile_id)))
    ctx.on_cleanup(lambda: _delete_if_present(lambda: b2bi.delete_transformer(transformerId=transformer_id)))
    ctx.on_cleanup(lambda: _delete_if_present(lambda: b2bi.delete_capability(capabilityId=capability_id)))
    ctx.on_cleanup(lambda: _delete_if_present(lambda: b2bi.delete_partnership(partnershipId=partnership_id)))


    # 1. transformer is referenced by the capability -> DeleteTransformer must reject.
    code, message = _error(lambda: b2bi.delete_transformer(transformerId=transformer_id))
    assert code == "ConflictException", f"expected ConflictException deleting a referenced transformer, got {code}"
    expected = "Transformer config is currently in use by a Capability"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    intact = b2bi.get_transformer(transformerId=transformer_id)["transformerId"]
    assert intact == transformer_id, f"rejected delete must leave the transformer intact, got id {intact!r}"

    # 2. capability is referenced by the partnership -> DeleteCapability must reject.
    code, message = _error(lambda: b2bi.delete_capability(capabilityId=capability_id))
    assert code == "ConflictException", f"expected ConflictException deleting a referenced capability, got {code}"
    expected = f"Partnership still exists for capability ID {capability_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    intact = b2bi.get_capability(capabilityId=capability_id)["capabilityId"]
    assert intact == capability_id, f"rejected delete must leave the capability intact, got id {intact!r}"

    # 3. profile has an active partnership -> DeleteProfile must reject.
    code, message = _error(lambda: b2bi.delete_profile(profileId=profile_id))
    assert code == "ConflictException", f"expected ConflictException deleting a profile with a partnership, got {code}"
    expected = f"Partnership still exists for profile ID {profile_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    intact = b2bi.get_profile(profileId=profile_id)["profileId"]
    assert intact == profile_id, f"rejected delete must leave the profile intact, got id {intact!r}"

    # Positive control: delete in dependency order and each step now succeeds cleanly.
    b2bi.delete_partnership(partnershipId=partnership_id)
    code, message = _error(lambda: b2bi.get_partnership(partnershipId=partnership_id))
    assert code == "ResourceNotFoundException", f"expected the deleted partnership to be gone, got {code}"
    expected = f"Partnership with partnershipId {partnership_id} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    b2bi.delete_capability(capabilityId=capability_id)
    code, message = _error(lambda: b2bi.get_capability(capabilityId=capability_id))
    assert code == "ResourceNotFoundException", f"expected the deleted capability to be gone, got {code}"
    expected = f"Capability ID {capability_id} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    b2bi.delete_transformer(transformerId=transformer_id)
    code, message = _error(lambda: b2bi.get_transformer(transformerId=transformer_id))
    assert code == "ResourceNotFoundException", f"expected the deleted transformer to be gone, got {code}"
    expected = f"Transformer not found with ID {transformer_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    b2bi.delete_profile(profileId=profile_id)
    code, message = _error(lambda: b2bi.get_profile(profileId=profile_id))
    assert code == "ResourceNotFoundException", f"expected the deleted profile to be gone, got {code}"
    expected = f"Profile ID {profile_id} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
