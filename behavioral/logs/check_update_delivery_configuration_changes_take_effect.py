"""update-delivery-configuration-changes-take-effect."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-delivery-configuration-changes-take-effect"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDeliveryConfiguration on an existing delivery is reflected on the next
    GetDelivery and DescribeDeliveries call."""
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    dest_bucket = _create_bucket(ctx, "deldest")
    dest_bucket_arn = f"arn:aws:s3:::{dest_bucket}"
    _apply_delivery_bucket_policy(ctx, dest_bucket, account_id)

    src_bucket = _create_bucket(ctx, "delsrc")
    src_bucket_arn = f"arn:aws:s3:::{src_bucket}"

    dest_name = ctx.unique_name("sim2real-behav-upddest-")
    dest_arn = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="S3",
        deliveryDestinationConfiguration={"destinationResourceArn": dest_bucket_arn},
    )["deliveryDestination"]["arn"]
    ctx.on_cleanup(lambda: logs.delete_delivery_destination(name=dest_name))

    src_name = ctx.unique_name("sim2real-behav-updsrc-")
    logs.put_delivery_source(
        name=src_name, resourceArn=src_bucket_arn, logType="S3_SERVER_ACCESS_LOGS"
    )
    ctx.on_cleanup(lambda: logs.delete_delivery_source(name=src_name))

    delivery_id = logs.create_delivery(
        deliverySourceName=src_name, deliveryDestinationArn=dest_arn
    )["delivery"]["id"]
    ctx.on_cleanup(lambda: logs.delete_delivery(id=delivery_id))

    baseline = logs.get_delivery(id=delivery_id)["delivery"]
    baseline_suffix = baseline.get("s3DeliveryConfiguration", {}).get("suffixPath", "")

    new_suffix = "/sim2real-behav/{account-id}"
    logs.update_delivery_configuration(
        id=delivery_id,
        s3DeliveryConfiguration={"enableHiveCompatiblePath": True, "suffixPath": new_suffix},
    )

    updated = logs.get_delivery(id=delivery_id)["delivery"]
    s3_config = updated["s3DeliveryConfiguration"]
    assert s3_config["suffixPath"] == new_suffix, (
        f"GetDelivery did not reflect the UpdateDeliveryConfiguration change: "
        f"expected suffixPath={new_suffix!r}, got {s3_config}"
    )
    assert s3_config["enableHiveCompatiblePath"] is True, (
        f"expected enableHiveCompatiblePath=True after update, got {s3_config}"
    )
    assert s3_config["suffixPath"] != baseline_suffix, (
        f"suffixPath unchanged from baseline {baseline_suffix!r} after update"
    )

    described = logs.describe_deliveries()["deliveries"]
    matches = [d for d in described if d["id"] == delivery_id]
    assert matches, f"delivery {delivery_id} missing from DescribeDeliveries"
    described_config = matches[0]["s3DeliveryConfiguration"]
    assert described_config["suffixPath"] == new_suffix, (
        f"DescribeDeliveries did not reflect the updated configuration: {described_config}"
    )
    assert described_config["enableHiveCompatiblePath"] is True, (
        f"DescribeDeliveries did not reflect enableHiveCompatiblePath=True: {described_config}"
    )


def _create_bucket(ctx, tag: str) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(f"sim2real-behav-{tag}-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    def _empty_and_delete_bucket() -> None:
        objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objects:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objects]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete_bucket)
    return bucket


def _apply_delivery_bucket_policy(ctx, bucket: str, account_id: str) -> None:
    s3 = ctx.client("s3")
    bucket_arn = f"arn:aws:s3:::{bucket}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSLogDeliveryWrite",
                "Effect": "Allow",
                "Principal": {"Service": "delivery.logs.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"{bucket_arn}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceAccount": account_id,
                    }
                },
            },
            {
                "Sid": "AWSLogDeliveryAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "delivery.logs.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": bucket_arn,
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
