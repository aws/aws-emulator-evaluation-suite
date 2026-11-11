"""appblockbuilder-appblock-association-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "appblockbuilder-appblock-association-lifecycle"
GROUP = "lifecycle"
SERVICES = ["appstream"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "requires:appstream-service-access")
def run(ctx) -> None:
    """A builder holds one associated app block: associating B while A is attached is refused with
    OperationNotPermittedException and leaves A alone, and after disassociating A the same call
    succeeds and the association reads back as B."""
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

    def _custom_app_block(suffix: str) -> str:
        name = ctx.unique_name(f"sim2real-appstream-appblock-{suffix}-")
        _put_object(ctx, bucket, f"src/{suffix}.zip")
        arn = appstream.create_app_block(
            Name=name,
            PackagingType="APPSTREAM2",
            SourceS3Location={"S3Bucket": bucket, "S3Key": f"src/{suffix}.zip"},
        )["AppBlock"]["Arn"]
        ctx.on_cleanup(lambda: appstream.delete_app_block(Name=name))
        return arn

    def _assoc_arns() -> set[str]:
        try:
            assocs = appstream.describe_app_block_builder_app_block_associations(
                AppBlockBuilderName=builder_name
            )["AppBlockBuilderAppBlockAssociations"]
        except appstream.exceptions.ResourceNotFoundException:
            return set()
        return {a["AppBlockArn"] for a in assocs}

    a_arn = _custom_app_block("a")
    b_arn = _custom_app_block("b")

    # positive control: associating the first app block while the builder is bare succeeds
    appstream.associate_app_block_builder_app_block(AppBlockArn=a_arn, AppBlockBuilderName=builder_name)
    assert _assoc_arns() == {a_arn}, "expected only A associated after the positive control"

    # break exactly one thing: associate a second app block while A is still attached
    code, message = _error(
        lambda: appstream.associate_app_block_builder_app_block(AppBlockArn=b_arn, AppBlockBuilderName=builder_name)
    )
    assert code == "OperationNotPermittedException", f"expected OperationNotPermittedException, got {code!r}"
    expected_message = "The selected App block builder can not be associated with additional App block"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: independent read still shows only A, never B
    after_break = _assoc_arns()
    assert after_break == {a_arn}, f"expected {{A}} unchanged after the rejected associate, got {after_break}"

    # restore: free the builder by disassociating A
    appstream.disassociate_app_block_builder_app_block(AppBlockArn=a_arn, AppBlockBuilderName=builder_name)
    assert _assoc_arns() == set(), "expected no associations once A is disassociated"

    # the identical associate-B call that was just rejected now succeeds
    appstream.associate_app_block_builder_app_block(AppBlockArn=b_arn, AppBlockBuilderName=builder_name)
    ctx.on_cleanup(
        lambda: appstream.disassociate_app_block_builder_app_block(AppBlockArn=b_arn, AppBlockBuilderName=builder_name)
    )

    # terminal independent read: B is associated, A is not
    terminal = _assoc_arns()
    assert terminal == {b_arn}, f"expected only B associated at the end, got {terminal}"


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
    # AppStream reads these objects via ACL-based ownership checks; ACLs are disabled by
    # default on new buckets (BucketOwnerEnforced), so opt back into BucketOwnerPreferred.
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
        CidrBlock="10.212.0.0/24",
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
            CidrBlock=f"10.212.0.{i * 128}/25",
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
