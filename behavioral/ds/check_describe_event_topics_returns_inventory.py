"""describe-event-topics-returns-inventory."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Directory Service cannot place domain controllers in these zones (CreateMicrosoftAD: "Failed to
# locate Availability Zone: us-west-2d"), so subnets there are never offered to it.
_DS_UNSUPPORTED_AZS = {"us-west-2d", "us-east-1e", "us-east-1f", "ca-central-1d"}

CHECK = "describe-event-topics-returns-inventory"
GROUP = 'lifecycle'
SERVICES = ['ds']
# Also calls sns (the topic) and ec2 (network for the directory); SERVICES names the service under test.

# Unique to this check: a run deletes the directory it creates, so no other check may find it.
_SHARED_MAD_NAME = "sim2ds5140e77d.sim2real.test"
_SHARED_MAD_VPC_TAG = "sim2real-ds-shared-mad-vpc3"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterEventTopic makes the topic appear in unfiltered and DirectoryId-scoped
    DescribeEventTopics with the real TopicArn; DeregisterEventTopic removes it from both.

    Reference: https://docs.aws.amazon.com/directoryservice/latest/devguide/API_DescribeEventTopics.html"""
    ds = ctx.client("ds")
    sns = ctx.client("sns")
    directory_id = _get_or_create_shared_microsoft_ad(ctx)

    topic_name = ctx.unique_name("sim2real-behav-").replace(".", "-")
    topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]
    ctx.on_cleanup(lambda: _safe(lambda: sns.delete_topic(TopicArn=topic_arn)))

    def _unfiltered():
        return ds.describe_event_topics()["EventTopics"]

    def _scoped():
        return ds.describe_event_topics(DirectoryId=directory_id)["EventTopics"]

    def _names(topics):
        return {t.get("TopicName") for t in topics}

    assert topic_name not in _names(_unfiltered()), (
        f"{topic_name} already present in the account-wide EventTopics inventory "
        f"before it was ever registered"
    )
    assert topic_name not in _names(_scoped()), (
        f"{topic_name} already present in DescribeEventTopics(DirectoryId={directory_id}) "
        f"before it was ever registered"
    )

    ds.register_event_topic(DirectoryId=directory_id, TopicName=topic_name)
    ctx.on_cleanup(lambda: _safe(
        lambda: ds.deregister_event_topic(DirectoryId=directory_id, TopicName=topic_name)
    ))

    unfiltered_after_register = _unfiltered()
    assert topic_name in _names(unfiltered_after_register), (
        f"RegisterEventTopic succeeded but {topic_name} is absent from the unfiltered "
        f"DescribeEventTopics inventory: {unfiltered_after_register}"
    )
    scoped_after_register = _scoped()
    assert topic_name in _names(scoped_after_register), (
        f"RegisterEventTopic succeeded but {topic_name} is absent from "
        f"DescribeEventTopics(DirectoryId={directory_id}): {scoped_after_register}"
    )

    entry = next(t for t in scoped_after_register if t.get("TopicName") == topic_name)
    assert entry.get("TopicArn") == topic_arn, (
        f"inventory entry TopicArn {entry.get('TopicArn')!r} does not match the real "
        f"SNS topic {topic_arn!r} -- DescribeEventTopics is not reporting the target's "
        f"own state"
    )
    assert entry.get("DirectoryId") == directory_id, (
        f"inventory entry DirectoryId {entry.get('DirectoryId')!r} != {directory_id!r}"
    )

    ds.deregister_event_topic(DirectoryId=directory_id, TopicName=topic_name)

    unfiltered_after_deregister = _unfiltered()
    assert topic_name not in _names(unfiltered_after_deregister), (
        f"DeregisterEventTopic succeeded but {topic_name} is still in the unfiltered "
        f"inventory: {unfiltered_after_deregister}"
    )
    scoped_after_deregister = _scoped()
    assert topic_name not in _names(scoped_after_deregister), (
        f"DeregisterEventTopic succeeded but {topic_name} is still in "
        f"DescribeEventTopics(DirectoryId={directory_id}): {scoped_after_deregister}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
            "NotFound",
        ):
            raise


def _mad_password() -> str:
    return "Sim2Real-Behav!9Qx"


def _find_directory_id_by_name(ctx, name):
    ds = ctx.client("ds")
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = ds.describe_directories(**kwargs)
        for desc in resp.get("DirectoryDescriptions", []):
            if desc.get("Name") == name and desc.get("Stage") not in ("Deleting", "Deleted"):
                return desc["DirectoryId"]
        next_token = resp.get("NextToken")
        if not next_token:
            return None


def _default_vpc_subnets(ctx):
    """Subnets of the shared network (DNS-enabled, one per AZ), avoiding a dedicated VPC."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnets = sorted((s for s in subnets if s["AvailabilityZone"] not in _DS_UNSUPPORTED_AZS), key=lambda s: s["AvailabilityZone"])
    by_az = {}
    for s in subnets:
        if s["State"] == "available":
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        return None
    return vpc_id, subnet_ids


def _get_or_create_shared_vpc(ctx, tag_name, cidr_base):
    default = _default_vpc_subnets(ctx)
    if default is not None:
        return default

    ec2 = ctx.client("ec2")

    def _existing():
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [tag_name]}])["Vpcs"]
        return sorted((v for v in vpcs if v["State"] != "deleting"), key=lambda v: v["VpcId"])

    vpcs = _existing()
    if not vpcs:
        try:
            ec2.create_vpc(
                CidrBlock=f"{cidr_base}.0.0/16",
                TagSpecifications=[{
                    "ResourceType": "vpc",
                    "Tags": [
                        {"Key": "Name", "Value": tag_name},
                        {"Key": "sim2real", "Value": "ds-behavioral"},
                    ],
                }],
            )
        except ClientError:
            pass
        for _ in range(15):
            vpcs = _existing()
            if vpcs:
                break
            time.sleep(2)
    if not vpcs:
        raise AssertionError(f"failed to create or find the shared VPC {tag_name}")
    vpc_id = vpcs[0]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets if s["State"] == "available"]
    if len(subnet_ids) >= 2:
        return vpc_id, subnet_ids[:2]

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not expose at least 2 available AZs for directory subnets")

    for i, az in enumerate(azs):
        try:
            subnet_id = ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=f"{cidr_base}.{i}.0/24",
                AvailabilityZone=az,
                TagSpecifications=[{
                    "ResourceType": "subnet",
                    "Tags": [
                        {"Key": "Name", "Value": f"{tag_name}-subnet{i}"},
                        {"Key": "sim2real", "Value": "ds-behavioral"},
                    ],
                }],
            )["Subnet"]["SubnetId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidSubnet.Conflict":
                continue
            raise
        ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        subnet_ids.append(subnet_id)
    if len(subnet_ids) < 2:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
        subnet_ids = [s["SubnetId"] for s in subnets if s["State"] == "available"]
    return vpc_id, subnet_ids[:2]


def _wait_directory_stage(ctx, directory_id, terminal_ok, terminal_bad, *, timeout_s=200.0, interval_s=10.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        resp = ds.describe_directories(DirectoryIds=[directory_id])
        descs = resp.get("DirectoryDescriptions", [])
        if not descs:
            raise AssertionError(f"directory {directory_id} vanished from DescribeDirectories while waiting")
        desc = descs[0]
        last_stage = desc["Stage"]
        if last_stage in terminal_ok:
            return desc
        if last_stage in terminal_bad:
            raise AssertionError(f"directory {directory_id} reached {last_stage}: {desc.get('StageReason')}")
        time.sleep(interval_s)
    raise AssertionError(
        f"shared directory {directory_id} still at stage={last_stage} after {timeout_s}s "
        "(AWS Managed Microsoft AD provisioning genuinely takes ~20-45 minutes; background "
        "provisioning continues regardless -- re-running validate_behavioral once it completes "
        "will find it Active immediately)"
    )


def _create_microsoft_ad_avoiding_constrained_azs(ctx, vpc_id):
    """CreateMicrosoftAD can reject an AZ as 'capacity constrained', a property of the AZ, so
    retrying the same pair fails again; try every AZ pair the VPC offers instead."""
    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")
    network_only = [{"Name": "subnet-id", "Values": ctx.network().subnet_ids}] if vpc_id == ctx.network().vpc_id else []
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, *network_only])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        if s["State"] == "available" and s["AvailabilityZone"] not in _DS_UNSUPPORTED_AZS:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    azs = sorted(by_az)
    if len(azs) < 2:
        raise AssertionError(f"VPC {vpc_id} does not have available subnets in >=2 AZs: {by_az}")

    last_exc = None
    for i in range(len(azs)):
        for j in range(i + 1, len(azs)):
            pair = [by_az[azs[i]], by_az[azs[j]]]
            try:
                resp = ds.create_microsoft_ad(
                    Name=_SHARED_MAD_NAME,
                    Password=_mad_password(),
                    Edition="Standard",
                    VpcSettings={"VpcId": vpc_id, "SubnetIds": pair},
                )
                return resp["DirectoryId"]
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                message = exc.response.get("Error", {}).get("Message", "")
                if code == "EntityAlreadyExistsException":
                    found = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
                    if found is not None:
                        return found
                    raise
                if code == "ClientException" and "capacity constrained" in message.lower():
                    last_exc = exc
                    continue
                raise
    raise last_exc or AssertionError(f"no viable AZ pair among {azs} for CreateMicrosoftAD")


def _get_or_create_shared_microsoft_ad(ctx) -> str:
    directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
    if directory_id is None:
        vpc_id, _ = _get_or_create_shared_vpc(ctx, _SHARED_MAD_VPC_TAG, "10.80")
        directory_id = _create_microsoft_ad_avoiding_constrained_azs(ctx, vpc_id)
    # The name is unique to this check, so the directory is this run's to remove, whether it was
    # created here or is a leftover of an earlier run of this check.
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ctx.client("ds"), directory_id))
    return _wait_directory_stage(ctx, directory_id, {"Active"}, {"Failed"}, timeout_s=2700.0)["DirectoryId"]


def _delete_directory_and_wait(ds, directory_id, timeout_s=1800.0, interval_s=30.0):
    """Delete a directory and wait until it is gone, so its ENIs and security group leave the
    shared network. DeleteDirectory is retried while the directory is still being created or is
    still shared with another account."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "EntityDoesNotExistException":
                return
            if "shared" in e.response["Error"].get("Message", "").lower():
                try:
                    shared = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
                except ClientError as share_err:
                    if share_err.response["Error"]["Code"] != "EntityDoesNotExistException":
                        raise
                    shared = []
                for share in shared:
                    try:
                        ds.unshare_directory(
                            DirectoryId=directory_id,
                            UnshareTarget={"Id": share["SharedAccountId"], "Type": "ACCOUNT"},
                        )
                    except ClientError as unshare_err:
                        if unshare_err.response["Error"]["Code"] not in (
                            "EntityDoesNotExistException", "DirectoryNotSharedException",
                        ):
                            raise
            elif code not in ("ClientException", "InvalidParameterException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while True:
        try:
            found = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        if not found or found[0].get("Stage") == "Deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"directory {directory_id} still exists {timeout_s:.0f}s after DeleteDirectory")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
