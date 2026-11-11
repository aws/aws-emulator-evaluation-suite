"""delete-stack-with-associated-fleet-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-stack-with-associated-fleet-rejected"
GROUP = "overly-permissive"
SERVICES = ["appstream"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "requires:appstream-service-access")
def run(ctx) -> None:
    """DeleteStack on a stack that still has an associated fleet is rejected with
    ResourceInUseException; the stack is left intact, and deleting it after disassociating
    the fleet (the positive control) succeeds."""
    appstream = ctx.client("appstream")
    from botocore.exceptions import ClientError

    vpc = _create_vpc(ctx)
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

    def _cleanup_fleet():
        # Defensive disassociate first: if the check body raised between associate_fleet and
        # disassociate_fleet, the fleet is still attached to the stack and a bare delete_fleet
        # would fail with ResourceInUseException, leaking both resources (cleanups are
        # best-effort and swallow exceptions individually -- see run_cleanups).
        _safe_disassociate(appstream, fleet_name, stack_name)
        appstream.delete_fleet(Name=fleet_name)

    stack_name = ctx.unique_name("sim2real-appstream-stack-")
    appstream.create_stack(Name=stack_name)
    stack_deleted = False

    def _cleanup_stack():
        if not stack_deleted:
            _safe_disassociate(appstream, fleet_name, stack_name)
            appstream.delete_stack(Name=stack_name)

    # Cleanups run LIFO, so registering the fleet cleanup first means it fires SECOND -- after
    # the stack (and its association) is already gone.
    ctx.on_cleanup(_cleanup_fleet)
    ctx.on_cleanup(_cleanup_stack)

    appstream.associate_fleet(FleetName=fleet_name, StackName=stack_name)

    code, message = _error(lambda: appstream.delete_stack(Name=stack_name))
    assert code == "ResourceInUseException", (
        f"DeleteStack on a stack with an associated fleet returned {code!r}, "
        f"expected 'ResourceInUseException'"
    )
    expected_message = (
        f"Cannot delete stack {stack_name}. This stack has fleets associated with it. "
        f"Only stacks with no fleets associated with it can be deleted."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the stack still exists and is still associated with the fleet
    described = appstream.describe_stacks(Names=[stack_name])["Stacks"]
    assert len(described) == 1, (
        f"the rejected DeleteStack removed the stack: describe_stacks returned "
        f"{len(described)} entries for {stack_name!r}, expected 1"
    )
    fleets_for_stack = appstream.list_associated_fleets(StackName=stack_name)["Names"]
    assert fleet_name in fleets_for_stack, (
        f"the rejected DeleteStack dropped the fleet association: {fleets_for_stack!r} does "
        f"not contain {fleet_name!r}"
    )

    # positive control: after disassociating, delete succeeds
    appstream.disassociate_fleet(FleetName=fleet_name, StackName=stack_name)
    appstream.delete_stack(Name=stack_name)
    stack_deleted = True

    try:
        deadline = time.monotonic() + 30
        remaining = [stack_name]
        while time.monotonic() < deadline:
            remaining = appstream.describe_stacks(Names=[stack_name])["Stacks"]
            if remaining == []:
                break
            time.sleep(2)
        assert remaining == [], (
            f"the deleted stack {stack_name!r} is still listed by describe_stacks after 30s: "
            f"{remaining!r}"
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"describe_stacks on the deleted stack {stack_name!r} raised {code!r}, "
            f"expected 'ResourceNotFoundException'"
        )
        message = err.response["Error"].get("Message")
        expected_message = f"The stack {stack_name} for account {ctx.account} does not exist."
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # deletes prove gone AND unusable: a mutation on the dead stack id also fails
    mutation_code, mutation_message = _error(
        lambda: appstream.associate_fleet(FleetName=fleet_name, StackName=stack_name)
    )
    assert mutation_code == "ResourceNotFoundException", (
        f"AssociateFleet against the deleted stack {stack_name!r} returned "
        f"{mutation_code!r}, expected 'ResourceNotFoundException'"
    )
    expected_mutation_message = f"The stack {stack_name} for account {ctx.account} does not exist."
    assert mutation_message == expected_mutation_message, (
        f"expected message {expected_mutation_message!r}, got {mutation_message!r}"
    )


# ===== helpers =====
def _ensure_fleet_role(ctx) -> str:
    """The IamRoleArn passed to CreateFleet is the 'machine role' assumed by streaming
    instances -- a distinct role from the account-level AppStream service-onboarding role.
    AppStream rejects reusing its own service-role as a fleet machine role, so this is a
    separate, shared (account-level) role."""
    import json

    iam = ctx.client("iam")
    role_name = "sim2real-appstream-fleet-machine-role"
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
    try:
        role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]
    except iam.exceptions.EntityAlreadyExistsException:
        role = iam.get_role(RoleName=role_name)["Role"]

    # NOTE: intentionally not torn down here -- shared account-level singleton that other
    # concurrently-running checks may depend on; deleting it per-check would race with them.
    return role["Arn"]


def _retry_role_propagation(fn, timeout_s: float = 90.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidRoleException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _create_vpc(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.214.0.0/24",
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
            CidrBlock=f"10.214.0.{i * 128}/25",
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
    SUCCESS raises AssertionError, because a target accepting a call real AWS refuses must not
    pass as a code mismatch against a falsy sentinel."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_disassociate(appstream, fleet_name: str, stack_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        appstream.disassociate_fleet(FleetName=fleet_name, StackName=stack_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
