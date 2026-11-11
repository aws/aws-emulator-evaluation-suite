"""launch-under-http-tokens-enforced-requires-required."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "launch-under-http-tokens-enforced-requires-required"
GROUP = "authorization"
SERVICES = ["ec2", "ssm"]

_VPC_CIDR = "10.83.0.0/16"
_SUBNET_CIDR = "10.83.1.0/24"
_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_ERR_UNSUPPORTED = "UnsupportedOperation"
_MSG_UNSUPPORTED = (
    "You can't launch instances with IMDSv1 because httpTokensEnforced is enabled for this "
    "account. Either launch the instance with httpTokens=required or contact your account owner "
    "to disable httpTokensEnforced using the ModifyInstanceMetadataDefaults API or the account "
    "settings in the EC2 console."
)
_GONE_CODES = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
               "InvalidInstanceID.NotFound")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control",
      "resource:account-singleton:ec2-instance-metadata-defaults")
def run(ctx) -> None:
    """RunInstances with MetadataOptions HttpTokens=optional is refused with UnsupportedOperation
    while the account enforces HttpTokensEnforced, launches nothing, and the identical request
    with HttpTokens=required succeeds.
    """
    ec2 = ctx.client("ec2")
    st: dict = {}
    _restore_account_defaults(ctx, ec2)
    _build(ctx, ec2, st)
    _legs(ctx, ec2, st)


def _restore_account_defaults(ctx, ec2) -> None:
    original = ec2.get_instance_metadata_defaults().get("AccountLevel") or {}
    if original.get("ManagedBy") == "declarative-policy":
        raise AssertionError(
            "instance metadata defaults are managed by a declarative policy in this account "
            "and cannot be modified directly by ModifyInstanceMetadataDefaults"
        )
    original_http_tokens = original.get("HttpTokens", "no-preference")
    original_hop_limit = original.get("HttpPutResponseHopLimit") or -1
    original_http_endpoint = original.get("HttpEndpoint", "no-preference")
    original_metadata_tags = original.get("InstanceMetadataTags", "no-preference")
    original_tokens_enforced = original.get("HttpTokensEnforced", "no-preference")

    def _restore():
        ec2.modify_instance_metadata_defaults(
            HttpTokens=original_http_tokens,
            HttpPutResponseHopLimit=original_hop_limit,
            HttpEndpoint=original_http_endpoint,
            InstanceMetadataTags=original_metadata_tags,
            HttpTokensEnforced=original_tokens_enforced,
        )

    ec2.modify_instance_metadata_defaults(HttpTokensEnforced="enabled")
    ctx.on_cleanup(_restore)

    current = ec2.get_instance_metadata_defaults()["AccountLevel"]
    assert current["HttpTokensEnforced"] == "enabled", (
        f"ModifyInstanceMetadataDefaults(HttpTokensEnforced=enabled) must be reflected by "
        f"GetInstanceMetadataDefaults, got {current!r}"
    )


def _legs(ctx, ec2, st) -> None:
    marker = ctx.unique_name("sim2real-httptok-")

    def launch(*, http_tokens):
        return ec2.run_instances(
            ImageId=st["ami"], InstanceType=_TYPE, MinCount=1, MaxCount=1,
            SubnetId=st["subnet"], SecurityGroupIds=[st["sg"]],
            MetadataOptions={"HttpTokens": http_tokens},
            TagSpecifications=[
                {"ResourceType": "instance", "Tags": _tags_for(marker)},
                {"ResourceType": "volume", "Tags": _tags_for(marker)},
            ],
        )

    err = _client_error(lambda: launch(http_tokens="optional"))
    assert (err.get("Code"), err.get("Message")) == (_ERR_UNSUPPORTED, _MSG_UNSUPPORTED), (
        f"RunInstances with HttpTokens=optional under HttpTokensEnforced=enabled must be refused "
        f"with {_ERR_UNSUPPORTED!r} and the exact IMDSv1-disabled message, got "
        f"{(err.get('Code'), err.get('Message'))!r}"
    )

    live = _by_marker(ec2, marker)
    assert live == set(), (
        f"the refused launch must have created no instance; DescribeInstances filtered on "
        f"tag:sim2real-marker={marker!r} must report nothing, got {sorted(live)!r}"
    )

    launched = launch(http_tokens="required")
    instance_id = launched["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_drain(ec2, instance_id, st["vpc"]))
    assert launched["Instances"][0]["MetadataOptions"]["HttpTokens"] == "required", (
        f"the real launch must report HttpTokens 'required', got "
        f"{launched['Instances'][0]['MetadataOptions']!r}"
    )

    described = _poll(
        lambda: _describe(ec2, instance_id),
        lambda i: i is not None,
        timeout_s=180.0, interval_s=5.0,
        what=f"instance {instance_id} becoming visible to DescribeInstances",
    )
    assert described["MetadataOptions"]["HttpTokens"] == "required", (
        f"DescribeInstances must report HttpTokens 'required' for {instance_id}, got "
        f"{described['MetadataOptions']!r}"
    )
    assert _by_marker(ec2, marker) == {instance_id}, (
        f"after the compliant launch, DescribeInstances filtered on tag:sim2real-marker="
        f"{marker!r} must report exactly {{{instance_id!r}}}, got {sorted(_by_marker(ec2, marker))!r}"
    )


# ===== the fixture ===========================================================


def _build(ctx, ec2, st) -> None:
    """A VPC and one private subnet of this check's own making."""
    name = ctx.unique_name("sim2real-httptok-")
    st["name"] = name

    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(name)}],
    )["Vpc"]["VpcId"]
    st["vpc"] = vpc_id
    ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc_id))
    ec2.get_waiter("vpc_available").wait(
        VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    offered = {
        o["Location"] for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"] for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, f"no available AZ offers {_TYPE!r} in {ctx.region}"
    az = usable[0]

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(name)}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    st["subnet"] = subnet_id

    sg_id = ec2.create_security_group(
        GroupName=name + "-sg", VpcId=vpc_id,
        Description="sim2real RunInstances HttpTokensEnforced check",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(name)}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_security_group(GroupId=sg_id)))
    st["sg"] = sg_id

    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} must resolve to an AMI id, got {ami!r}"
    st["ami"] = ami


def _terminate_and_drain(ec2, instance_id, vpc_id) -> None:
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
    _poll(
        lambda: _state(ec2, instance_id), lambda s: s in ("terminated", "__gone__"),
        timeout_s=600.0, interval_s=5.0, what=f"instance {instance_id} reaching 'terminated'")
    _poll(
        lambda: _vpc_enis(ec2, vpc_id), lambda enis: enis == [],
        timeout_s=420.0, interval_s=10.0, what=f"every ENI in {vpc_id!r} draining")


def _delete_vpc(ec2, vpc_id) -> None:
    _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id))
    try:
        still = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
    except ClientError as exc:
        if _code(exc) != "InvalidVpcID.NotFound":
            raise
        return
    raise AssertionError(f"vpc {vpc_id} is still describable after DeleteVpc: {still!r}")


# ===== helpers =====================================


def _tags_for(marker):
    return [{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-marker", "Value": marker}]


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


def _poll(probe, predicate, *, timeout_s, interval_s, what):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} was not observed within {timeout_s}s; last saw {last!r}")


def _retry_dependency(fn, attempts=24, delay=10.0):
    for attempt in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) in _GONE_CODES:
                return
            if _code(exc) not in ("DependencyViolation", "InvalidParameterDependency",
                                  "RequestLimitExceeded") or attempt == attempts - 1:
                raise
            time.sleep(delay)


def _describe(ec2, instance_id):
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    if not resv or not resv[0].get("Instances"):
        return None
    return resv[0]["Instances"][0]


def _state(ec2, instance_id):
    inst = _describe(ec2, instance_id)
    return "__gone__" if inst is None else inst["State"]["Name"]


def _by_marker(ec2, marker):
    found = set()
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "tag:sim2real-marker", "Values": [marker]}]):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                if inst["State"]["Name"] != "terminated":
                    found.add(inst["InstanceId"])
    return found


def _vpc_enis(ec2, vpc_id):
    return [
        eni["NetworkInterfaceId"]
        for page in ec2.get_paginator("describe_network_interfaces").paginate(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        for eni in page["NetworkInterfaces"]
    ]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
