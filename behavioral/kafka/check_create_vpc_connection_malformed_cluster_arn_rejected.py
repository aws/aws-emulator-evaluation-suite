"""create-vpc-connection-malformed-cluster-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-vpc-connection-malformed-cluster-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVpcConnection with a malformed TargetClusterArn (all else valid) is rejected.

    AccessDeniedException (IAM, with the exact denial message) or BadRequestException (Kafka input
    validation) are both refusals; either way no VPC connection is created as a side effect.
    """
    kafka = ctx.client("kafka")
    vpc_id, subnet_ids, sg_id = _create_vpc_infra(ctx)

    # Positive control: the client/credentials/service are generally healthy.
    kafka.list_vpc_connections()

    sts = ctx.client("sts")
    caller = sts.get_caller_identity()
    account_id = caller["Account"]
    cluster_name = ctx.unique_name("sim2real-behav-nonexistent-")
    # Well-formed ARN *prefix* (matches this account's own kafka cluster ARN shape and the
    # sim2real- naming convention) but with a structurally invalid trailing UUID segment.
    malformed_cluster_arn = f"arn:aws:kafka:{ctx.region}:{account_id}:cluster/{cluster_name}/not-a-valid-uuid"

    code, message = _error_code(
        lambda: kafka.create_vpc_connection(
            TargetClusterArn=malformed_cluster_arn,
            Authentication="SASL_IAM",
            VpcId=vpc_id,
            ClientSubnets=subnet_ids,
            SecurityGroups=[sg_id],
        )
    )
    # Which layer answers depends on the caller's IAM grant, not on Kafka, so both codes are
    # accepted. An authorization-time refusal must still be the exact IAM denial for this caller.
    assert code in ("AccessDeniedException", "BadRequestException"), repr(code)
    if code == "AccessDeniedException":
        expected_message = (
            f"User: {caller['Arn']} is not authorized to perform: kafka:CreateVpcConnection "
            "on resource: *"
        )
        assert message == expected_message, f"unexpected message: {message!r}"

    # Effect absent: no VPC connection exists in this check's own VPC after the rejected call.
    created = [c for c in _vpc_connections(kafka) if c.get("VpcId") == vpc_id]
    assert not created, f"expected no VpcConnection in {vpc_id}, got {created!r}"



def _vpc_connections(kafka) -> list:
    """Every VPC connection in the account, read across all pages."""
    return [
        c
        for page in kafka.get_paginator("list_vpc_connections").paginate()
        for c in page.get("VpcConnections", [])
    ]


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp}")


def _create_vpc_infra(ctx):
    """Build this check's own VPC/subnets/security-group instead of depending on
    an ambient default VPC, which a freshly provisioned account may not have."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpcconn-")
    tag_spec = lambda rt: [{"ResourceType": rt, "Tags": [{"Key": "Name", "Value": name}]}]

    vpc_id = ec2.create_vpc(CidrBlock="10.97.0.0/16", TagSpecifications=tag_spec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    az_names = [a["ZoneName"] for a in azs[:2]]
    if len(az_names) < 2:
        raise AssertionError(f"region {ctx.region} does not offer >=2 availability zones")
    subnet_ids = []
    for i, az in enumerate(az_names):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.97.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=tag_spec("subnet"),
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(sid)

    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral check: create-vpc-connection-malformed-cluster-arn-rejected",
        VpcId=vpc_id,
        TagSpecifications=tag_spec("security-group"),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return vpc_id, subnet_ids, sg_id


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation, and swallowing that leaks the VPC.
# So wait (bounded) for the resource's ENIs to go, retry DependencyViolation inside the same window,
# and raise a final failure naming the ENIs still attached. Every other error propagates.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits the suite's cleanup budget.
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
