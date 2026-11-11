"""project-vpc-config-validates-against-real-ec2-subnets."""
from __future__ import annotations

import re
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "project-vpc-config-validates-against-real-ec2-subnets"
GROUP = 'vpc-config'
SERVICES = ['devicefarm']

_NET_TEARDOWN_S = 180.0
_REQUEST_ID_RE = re.compile(r"Request ID: [0-9a-f-]+")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _delete_with_dependency_retry(fn, deadline: float):
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(10)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateProject's vpcConfig is validated against real EC2: a real subnet/SG/VPC is
    accepted and persists, a well-formed but nonexistent subnet id is rejected, and the
    rejected update leaves the project's prior vpcConfig unchanged.
    """
    ec2 = ctx.client("ec2")
    df = ctx.client("devicefarm")
    deadline = time.monotonic() + _NET_TEARDOWN_S

    tag_value = ctx.unique_name("sim2real-behav-df-vpc-")
    net_tags = [{"Key": "Name", "Value": tag_value}]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.78.0.0/24", TagSpecifications=[{"ResourceType": "vpc", "Tags": net_tags}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: _delete_with_dependency_retry(
        lambda: ec2.delete_vpc(VpcId=vpc_id), deadline), "InvalidVpcID.NotFound"))

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.78.0.0/25", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": net_tags}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(_teardown(lambda: _delete_with_dependency_retry(
        lambda: ec2.delete_subnet(SubnetId=subnet_id), deadline), "InvalidSubnetID.NotFound"))

    sg_id = ec2.create_security_group(
        GroupName=tag_value, Description="sim2real device farm vpc config check", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": net_tags}],
    )["GroupId"]
    ctx.on_cleanup(_teardown(lambda: _delete_with_dependency_retry(
        lambda: ec2.delete_security_group(GroupId=sg_id), deadline), "InvalidGroup.NotFound"))

    project_name = ctx.unique_name("sim2real-behav-df-vpc-project-")
    project_arn = df.create_project(name=project_name)["project"]["arn"]
    ctx.on_cleanup(_teardown(lambda: df.delete_project(arn=project_arn), "NotFoundException"))

    good_config = {"securityGroupIds": [sg_id], "subnetIds": [subnet_id], "vpcId": vpc_id}
    updated = df.update_project(arn=project_arn, vpcConfig=good_config)["project"]
    assert updated["vpcConfig"] == good_config, (
        f"expected vpcConfig {good_config!r} to persist, got {updated['vpcConfig']!r}"
    )
    persisted = df.get_project(arn=project_arn)["project"]
    assert persisted["vpcConfig"] == good_config, (
        f"a later GetProject read back vpcConfig {persisted['vpcConfig']!r}, expected {good_config!r}"
    )

    # Negative: a well-formed but nonexistent subnet id is validated against real EC2 and
    # rejected, and the rejected update must not clobber the project's existing vpcConfig.
    missing_subnet_id = "subnet-" + uuid.uuid4().hex[:17]
    bad_config = {"securityGroupIds": [sg_id], "subnetIds": [missing_subnet_id], "vpcId": vpc_id}
    code, message = _error(lambda: df.update_project(arn=project_arn, vpcConfig=bad_config))
    assert code == "ArgumentException", f"expected ArgumentException, got {code}"
    # Device Farm forwards EC2's own validation error verbatim, including EC2's own request id
    # for that nested call; redact only that one unknowable token before the exact comparison.
    expected_message = (
        f"The subnet ID '{missing_subnet_id}' does not exist (Service: AmazonEC2; "
        f"Status Code: 400; Error Code: InvalidSubnetID.NotFound; Request ID: <redacted>)"
    )
    assert _REQUEST_ID_RE.sub("Request ID: <redacted>", message) == expected_message, (
        f"expected {expected_message!r}, got {message!r}"
    )

    unchanged = df.get_project(arn=project_arn)["project"]
    assert unchanged["vpcConfig"] == good_config, (
        f"the rejected update changed vpcConfig to {unchanged['vpcConfig']!r}, "
        f"expected the prior {good_config!r} to survive untouched"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
