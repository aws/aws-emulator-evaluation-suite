"""vpc-connection-malformed-target-cluster-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "vpc-connection-malformed-target-cluster-rejected"
GROUP = "overly-permissive"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVpcConnection with a TargetClusterArn that is not an ARN fails with AccessDeniedException
    naming the caller and resource "*", and ListVpcConnections then shows no connection targeting that
    value."""
    kafka = ctx.client("kafka")
    ec2 = ctx.client("ec2")

    vpc_id, subnets = _default_vpc_subnets(ctx, 2)
    sg_id = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"][0]["GroupId"]

    # Positive control: the service is reachable and normal read calls succeed.
    kafka.list_vpc_connections()

    # Negative: not ARN-shaped at all.
    code = _client_error_code(
        ctx,
        kafka,
        lambda: kafka.create_vpc_connection(
            TargetClusterArn="not-an-arn-at-all",
            Authentication="SASL_IAM",
            VpcId=vpc_id,
            ClientSubnets=subnets,
            SecurityGroups=[sg_id],
        ),
    )
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    expected = (
        "AccessDeniedException",
        f"User: {caller_arn} is not authorized to perform: kafka:CreateVpcConnection on resource: *",
    )
    assert code == expected, f"expected {expected!r}, got {code!r}"

    # Effect absent: an independent read at the destination proves no VPC connection
    # was created by the rejected call.
    created = [c for c in _vpc_connections(kafka) if c.get("TargetClusterArn") == "not-an-arn-at-all"]
    assert not created, f"a rejected CreateVpcConnection must not create a VPC connection, got {created!r}"


def _vpc_connections(kafka) -> list:
    """Every VPC connection in the account, read across all pages."""
    return [
        c
        for page in kafka.get_paginator("list_vpc_connections").paginate()
        for c in page.get("VpcConnections", [])
    ]


def _default_vpc_subnets(ctx, count=2):


    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to exercise CreateVpcConnection")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < count:
        raise AssertionError("shared network lacks enough distinct-AZ subnets for CreateVpcConnection")
    return vpc_id, subnet_ids[:count]


def _client_error_code(ctx, kafka, fn):
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    arn = resp.get("VpcConnectionArn")
    if arn:
        ctx.on_cleanup(lambda: kafka.delete_vpc_connection(Arn=arn))
    raise AssertionError(
        f"real AWS rejects a non-ARN-shaped TargetClusterArn, but CreateVpcConnection "
        f"SUCCEEDED and returned {resp!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
