"""application-fleet-association-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "application-fleet-association-lifecycle"
GROUP = "lifecycle"
SERVICES = ["appstream"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "requires:appstream-service-access")
def run(ctx) -> None:
    """AssociateApplicationFleet links an app to a fleet (visible via
    DescribeApplicationFleetAssociations); disassociating removes it, and disassociating an
    already-removed pair succeeds idempotently (no not-found error is documented)."""
    appstream = ctx.client("appstream")
    vpc = _create_vpc(ctx)
    bucket = _create_asset_bucket(ctx)
    _put_object(ctx, bucket, "pkg/app.zip")
    _put_object(ctx, bucket, "icons/app.png")
    role_arn = _ensure_fleet_role(ctx)

    fleet_name = ctx.unique_name("sim2real-appstream-fleet-")
    _retry_role_propagation(
        lambda: appstream.create_fleet(
            Name=fleet_name,
            InstanceType="stream.standard.small",
            FleetType="ELASTIC",
            Platform="WINDOWS_SERVER_2019",
            MaxConcurrentSessions=5,
            VpcConfig={"SubnetIds": vpc["subnet_ids"]},
            IamRoleArn=role_arn,
        )
    )
    ctx.on_cleanup(lambda: appstream.delete_fleet(Name=fleet_name))

    appblock_name = ctx.unique_name("sim2real-appstream-appblock-")
    appblock_arn = appstream.create_app_block(
        Name=appblock_name,
        PackagingType="APPSTREAM2",
        SourceS3Location={"S3Bucket": bucket, "S3Key": "pkg/app.zip"},
    )["AppBlock"]["Arn"]
    ctx.on_cleanup(lambda: appstream.delete_app_block(Name=appblock_name))

    app_name = ctx.unique_name("sim2real-appstream-app-")
    app_arn = appstream.create_application(
        Name=app_name,
        IconS3Location={"S3Bucket": bucket, "S3Key": "icons/app.png"},
        LaunchPath="C:\\app\\app.exe",
        Platforms=["WINDOWS_SERVER_2019"],
        InstanceFamilies=["GENERAL_PURPOSE"],
        AppBlockArn=appblock_arn,
    )["Application"]["Arn"]
    ctx.on_cleanup(lambda: appstream.delete_application(Name=app_name))

    appstream.associate_application_fleet(FleetName=fleet_name, ApplicationArn=app_arn)

    assocs = appstream.describe_application_fleet_associations(FleetName=fleet_name)[
        "ApplicationFleetAssociations"
    ]
    assert any(a["ApplicationArn"] == app_arn for a in assocs)

    appstream.disassociate_application_fleet(FleetName=fleet_name, ApplicationArn=app_arn)

    assocs_after = appstream.describe_application_fleet_associations(FleetName=fleet_name)[
        "ApplicationFleetAssociations"
    ]
    assert not any(a["ApplicationArn"] == app_arn for a in assocs_after)

    # disassociating a pair that no longer exists is idempotent (no error) rather than
    # rejected -- the Smithy model's error list for DisassociateApplicationFleet is
    # ConcurrentModificationException / InvalidParameterCombinationException /
    # OperationNotPermittedException only, with no not-found error for this case
    appstream.disassociate_application_fleet(FleetName=fleet_name, ApplicationArn=app_arn)

    assocs_final = appstream.describe_application_fleet_associations(FleetName=fleet_name)[
        "ApplicationFleetAssociations"
    ]
    assert not any(a["ApplicationArn"] == app_arn for a in assocs_final), (
        "double disassociate must not resurrect or duplicate the association"
    )


# ===== helpers =====
def _ensure_fleet_role(ctx) -> str:
    """The IamRoleArn passed to CreateFleet is the 'machine role' assumed by streaming
    instances -- a distinct role from the account-level AppStream service-onboarding role.
    AppStream rejects reusing its own service-role as a fleet machine role, so the check
    creates its own uniquely named role and deletes it on cleanup."""
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-appstream-fleet-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "appstream.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Arn"]


def _retry_role_propagation(fn, timeout_s: float = 90.0):
    """Retry fn() while AppStream reports the service role as not-yet-valid (IAM
    eventual consistency shortly after role/policy creation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidRoleException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _create_asset_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-appstream-assets-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":  # CreateBucket rejects an explicit LocationConstraint for us-east-1
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


def _create_vpc(ctx) -> dict[str, object]:
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.213.0.0/24",
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

    # ELASTIC fleets require >=2 subnets in different AZs
    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.213.0.{i * 128}/25",
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


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation, and swallowing that would leak the
# VPC while the check passed. So wait (bounded) for the resource's ENIs to go, retry
# DependencyViolation inside the same window, and raise a final failure naming the ENIs still
# attached. Every other error propagates.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits the suite's 900s cleanup budget here.
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
