"""dataflow-endpoint-group-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dataflow-endpoint-group-lifecycle"
GROUP = "crud"
SERVICES = ["groundstation"]


def _error(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _tolerate_not_found(fn):
    """Run a cleanup delete; the check may already have deleted the resource."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataflowEndpointGroup without securityDetails raises InvalidParameterException; with
    them the group keeps its endpoint address, and after deletion Get and Delete raise
    ResourceNotFoundException with exact messages.
    """
    gs = ctx.client("groundstation")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    endpoint_name = ctx.unique_name("sim2real-gs-ep-")

    # securityDetails omitted entirely -> rejected, despite the API doc marking it optional.
    refused = _error(
        lambda: gs.create_dataflow_endpoint_group(
            endpointDetails=[
                {
                    "endpoint": {
                        "name": endpoint_name,
                        "address": {"name": "10.0.0.5", "port": 55888},
                    }
                }
            ],
        )
    )
    assert refused == (
        "InvalidParameterException",
        "EndpointDetails securityDetails cannot be null",
    ), f"unexpected outcome without securityDetails: {refused!r}"

    # The network the endpoint group's securityDetails reference is created here, not assumed.
    vpc_tags = [{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": CHECK}]}]
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16", TagSpecifications=vpc_tags)["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    zone = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_tags = [{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": CHECK}]}]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.0.0.0/24", AvailabilityZone=zone, TagSpecifications=subnet_tags
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    sg_tags = [{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": CHECK}]}]
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-gs-sg-"),
        Description="sim2real dataflow endpoint group",
        VpcId=vpc_id,
        TagSpecifications=sg_tags,
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))

    role_name = ctx.unique_name("sim2real-gs-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "groundstation.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    created = gs.create_dataflow_endpoint_group(
        endpointDetails=[
            {
                "endpoint": {
                    "name": endpoint_name,
                    "address": {"name": "10.0.0.5", "port": 55888},
                },
                "securityDetails": {
                    "subnetIds": [subnet_id],
                    "securityGroupIds": [sg_id],
                    "roleArn": role_arn,
                },
            }
        ],
    )
    group_id = created["dataflowEndpointGroupId"]
    ctx.on_cleanup(lambda: _tolerate_not_found(
        lambda: gs.delete_dataflow_endpoint_group(dataflowEndpointGroupId=group_id)))

    fetched = gs.get_dataflow_endpoint_group(dataflowEndpointGroupId=group_id)
    details = fetched["endpointsDetails"]
    assert len(details) == 1, f"expected exactly 1 endpoint detail, got {len(details)}: {details!r}"
    endpoint = details[0]["endpoint"]
    assert endpoint["name"] == endpoint_name, f"expected endpoint name {endpoint_name!r}, got {endpoint['name']!r}"
    assert endpoint["address"] == {"name": "10.0.0.5", "port": 55888}, (
        f"expected persisted address {{'name': '10.0.0.5', 'port': 55888}}, got {endpoint['address']!r}"
    )

    gs.delete_dataflow_endpoint_group(dataflowEndpointGroupId=group_id)
    refused = _error(lambda: gs.get_dataflow_endpoint_group(dataflowEndpointGroupId=group_id))
    assert refused == ("ResourceNotFoundException", "The specified group does not exist."), (
        f"expected ResourceNotFoundException on get after delete, got {refused!r}"
    )

    # The dead id must also reject a mutation, not just a read: gone AND unusable.
    refused = _error(lambda: gs.delete_dataflow_endpoint_group(dataflowEndpointGroupId=group_id))
    assert refused == (
        "ResourceNotFoundException",
        f"No Dataflow Endpoint Group found with id {group_id}",
    ), f"expected ResourceNotFoundException on re-delete of {group_id}, got {refused!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
