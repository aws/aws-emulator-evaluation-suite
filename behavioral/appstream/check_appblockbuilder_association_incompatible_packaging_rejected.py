"""appblockbuilder-association-incompatible-packaging-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "appblockbuilder-association-incompatible-packaging-rejected"
GROUP = "overly-permissive"
SERVICES = ["appstream"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "requires:appstream-service-access")
def run(ctx) -> None:
    """Associating a CUSTOM-packaged app block (it needs no builder) with an app block builder is
    rejected with InvalidParameterValueException and creates nothing, while an APPSTREAM2-packaged
    app block associates."""
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

    incompatible_name = ctx.unique_name("sim2real-appstream-appblock-incompat-")
    _put_object(ctx, bucket, "pkg/incompat.zip")
    _put_object(ctx, bucket, "scripts/setup.ps1")
    incompatible_arn = appstream.create_app_block(
        Name=incompatible_name,
        PackagingType="CUSTOM",
        SourceS3Location={"S3Bucket": bucket, "S3Key": "pkg/incompat.zip"},
        SetupScriptDetails={
            "ScriptS3Location": {"S3Bucket": bucket, "S3Key": "scripts/setup.ps1"},
            "ExecutablePath": "setup.ps1",
            "TimeoutInSeconds": 60,
        },
    )["AppBlock"]["Arn"]
    ctx.on_cleanup(lambda: appstream.delete_app_block(Name=incompatible_name))

    code, message = _error(
        lambda: appstream.associate_app_block_builder_app_block(
            AppBlockArn=incompatible_arn, AppBlockBuilderName=builder_name
        )
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException associating a CUSTOM-packaged app block, got {code!r}"
    )
    expected_message = "The selected App block does not support the association operation"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the builder lists no association at all (real AWS returns an empty list)
    assocs = appstream.describe_app_block_builder_app_block_associations(AppBlockBuilderName=builder_name)[
        "AppBlockBuilderAppBlockAssociations"
    ]
    assert assocs == [], f"expected no associations after the rejected associate, got {assocs!r}"

    # positive control: an APPSTREAM2-packaged app block associates successfully
    compatible_name = ctx.unique_name("sim2real-appstream-appblock-compat-")
    _put_object(ctx, bucket, "src/compat.zip")
    compatible_arn = appstream.create_app_block(
        Name=compatible_name,
        PackagingType="APPSTREAM2",
        SourceS3Location={"S3Bucket": bucket, "S3Key": "src/compat.zip"},
    )["AppBlock"]["Arn"]
    ctx.on_cleanup(lambda: appstream.delete_app_block(Name=compatible_name))
    ctx.on_cleanup(
        lambda: appstream.disassociate_app_block_builder_app_block(
            AppBlockArn=compatible_arn, AppBlockBuilderName=builder_name
        )
    )

    appstream.associate_app_block_builder_app_block(AppBlockArn=compatible_arn, AppBlockBuilderName=builder_name)
    assocs_after = appstream.describe_app_block_builder_app_block_associations(AppBlockBuilderName=builder_name)[
        "AppBlockBuilderAppBlockAssociations"
    ]
    assert any(a["AppBlockArn"] == compatible_arn for a in assocs_after), (
        f"expected {compatible_arn} among associations after a successful associate, got {assocs_after!r}"
    )


# ===== helpers =====
def _retry_builder_limit(fn, timeout_s: float = 600.0):
    """CreateAppBlockBuilder retries InvalidRoleException and the account-level
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


def _create_asset_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-appstream-assets-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_ownership_controls(
        Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}
    )
    import json

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


def _create_vpc(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.216.0.0/24",
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

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.216.0.{i * 128}/25",
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
    return {"vpc_id": vpc_id, "subnet_id": subnet_ids[0], "subnet_ids": subnet_ids}


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
