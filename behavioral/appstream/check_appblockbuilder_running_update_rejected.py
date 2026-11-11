"""appblockbuilder-running-update-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "appblockbuilder-running-update-rejected"
GROUP = "state"
SERVICES = ["appstream"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "requires:appstream-service-access")
def run(ctx) -> None:
    """UpdateAppBlockBuilder is rejected with ResourceInUseException while the builder is
    RUNNING; its InstanceType is left untouched, and the same update after StopAppBlockBuilder
    drains it to STOPPED (the positive control) succeeds."""
    appstream = ctx.client("appstream")
    vpc = _create_vpc(ctx)
    bucket = _create_asset_bucket(ctx)

    builder_name = ctx.unique_name("sim2real-appstream-abb-")
    _retry_builder_limit(
        lambda: appstream.create_app_block_builder(
            Name=builder_name,
            Platform="WINDOWS_SERVER_2019",
            InstanceType="stream.standard.small",
            VpcConfig={"SubnetIds": vpc["subnet_ids"]},
        )
    )
    ctx.on_cleanup(lambda: appstream.delete_app_block_builder(Name=builder_name))

    # a builder cannot start while unassociated with any app block
    app_block_name = ctx.unique_name("sim2real-appstream-appblock-")
    _put_object(ctx, bucket, "src/asset.zip")
    app_block_arn = appstream.create_app_block(
        Name=app_block_name,
        PackagingType="APPSTREAM2",
        SourceS3Location={"S3Bucket": bucket, "S3Key": "src/asset.zip"},
    )["AppBlock"]["Arn"]
    ctx.on_cleanup(lambda: appstream.delete_app_block(Name=app_block_name))
    appstream.associate_app_block_builder_app_block(AppBlockArn=app_block_arn, AppBlockBuilderName=builder_name)
    ctx.on_cleanup(
        lambda: appstream.disassociate_app_block_builder_app_block(
            AppBlockArn=app_block_arn, AppBlockBuilderName=builder_name
        )
    )

    appstream.start_app_block_builder(Name=builder_name)
    ctx.on_cleanup(lambda: _stop_builder_for_teardown(appstream, builder_name))
    _wait_for_state(ctx, builder_name, "RUNNING", timeout_s=1200)

    code, message = _error(
        lambda: appstream.update_app_block_builder(Name=builder_name, InstanceType="stream.standard.medium")
    )
    assert code == "ResourceInUseException", (
        f"updating a RUNNING app block builder returned error code {code!r}, expected "
        f"'ResourceInUseException'"
    )
    expected_message = (
        f"Cannot update the attributes for AppBlockBuilder {builder_name} when it is in RUNNING state. "
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    described = appstream.describe_app_block_builders(Names=[builder_name])["AppBlockBuilders"][0]
    assert described["InstanceType"] == "stream.standard.small", (
        f"the rejected update still moved InstanceType to {described['InstanceType']!r}; "
        f"a refused update must leave it at 'stream.standard.small'"
    )

    # positive control: stop, then the same update succeeds
    appstream.stop_app_block_builder(Name=builder_name)
    _wait_for_state(ctx, builder_name, "STOPPED", timeout_s=600)

    appstream.update_app_block_builder(Name=builder_name, InstanceType="stream.standard.medium")
    described_after = appstream.describe_app_block_builders(Names=[builder_name])["AppBlockBuilders"][0]
    assert described_after["InstanceType"] == "stream.standard.medium", (
        f"after stopping the builder, the identical update left InstanceType at "
        f"{described_after['InstanceType']!r}, expected it to take effect and read back as "
        f"'stream.standard.medium'"
    )


# ===== helpers =====
def _create_vpc(ctx) -> dict[str, object]:
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.220.0.0/24",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-appstream-vpc-")}],
            }
        ],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        state = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]
        if state == "available":
            break
        time.sleep(1)

    # AppBlockBuilder requires at least two subnets in distinct AZs.
    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.220.0.{i * 128}/25",
            AvailabilityZone=az,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-appstream-subnet-")}],
                }
            ],
        )["Subnet"]
        subnet_id = subnet["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _create_asset_bucket(ctx) -> str:
    import json

    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-appstream-assets-").lower().replace("_", "-")
    region = ctx.region
    # not a region pin: S3's CreateBucket rejects an explicit LocationConstraint of us-east-1.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    # AppStream reads these objects via ACL-based ownership checks; ACLs are disabled by
    # default on new buckets (BucketOwnerEnforced), so opt back into BucketOwnerPreferred.
    s3.put_bucket_ownership_controls(
        Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}
    )
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowAppStream2Access",
                        "Effect": "Allow",
                        "Principal": {"Service": "appstream.amazonaws.com"},
                        "Action": [
                            "s3:GetObject",
                            "s3:ListBucket",
                            "s3:PutObject",
                            "s3:GetBucketOwnershipControls",
                        ],
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    }
                ],
            }
        ),
    )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _put_object(ctx, bucket: str, key: str) -> None:
    ctx.client("s3").put_object(
        Bucket=bucket, Key=key, Body=b"sim2real-appstream-asset", ACL="bucket-owner-full-control"
    )


def _wait_for_state(ctx, builder_name: str, target_state: str, timeout_s: float) -> None:
    appstream = ctx.client("appstream")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        described = appstream.describe_app_block_builders(Names=[builder_name])["AppBlockBuilders"][0]
        last_state = described["State"]
        if last_state == target_state:
            return
        time.sleep(2)
    raise AssertionError(f"app block builder never reached {target_state}, last state was {last_state}")


def _stop_builder_for_teardown(appstream, builder_name: str, timeout_s: float = 600.0) -> None:
    """Teardown: a builder must be STOPPED before it can be disassociated or deleted, including
    when the body fails while it is still RUNNING."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = appstream.describe_app_block_builders(Names=[builder_name])["AppBlockBuilders"][0]["State"]
        if state == "STOPPED":
            return
        if state == "RUNNING":
            try:
                appstream.stop_app_block_builder(Name=builder_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        time.sleep(10)
    raise RuntimeError(f"app block builder {builder_name} did not reach STOPPED during teardown")


def _retry_builder_limit(fn, timeout_s: float = 600.0):
    """CreateAppBlockBuilder retries on both IAM propagation lag and the account-level
    concurrent-AppBlockBuilder limit (stream.standard.small allows only 1 concurrently in
    the account/region -- transient while other checks' builders are torn down)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("InvalidRoleException", "LimitExceededException") or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _error(fn):
    """Call fn(); return the (code, message) of the botocore error it raises. An unexpected
    success raises AssertionError, so an accepted call never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A resource in this
# VPC deletes asynchronously, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails
# with DependencyViolation while its ENIs remain: retry that code inside one shared window, then
# raise naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
