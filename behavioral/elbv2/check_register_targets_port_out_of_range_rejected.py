"""register-targets-port-out-of-range-rejected."""
from __future__ import annotations

import time
import ipaddress

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-targets-port-out-of-range-rejected"
GROUP = "negative-classes"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterTargets with a Port outside 1-65535 fails with ValidationError and the exact message and registers
    nothing, while the same target id on port 8080 registers."""
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_cidr = _vpc_and_subnet_cidr(ctx)
    target_ip = _pick_host_ip(subnet_cidr)

    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-porttg-"), Protocol="HTTP", Port=80,
        VpcId=vpc_id, TargetType="ip",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))

    # A ctx client with client-side parameter validation disabled: the shape's declared
    # range (1-65535) would otherwise be caught by botocore BEFORE any request is sent,
    # which would test the SDK, not the service.
    raw = _unvalidated_client(ctx, "elbv2")

    def _bad_register():
        raw.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": target_ip, "Port": 70000}])

    code, message = _error(_bad_register)
    assert code == "ValidationError", f"CODE={code!r}"
    expected = (
        "1 validation error detected: Value '70000' at 'targets.1.member.port' failed to satisfy "
        "constraint: Member must have value less than or equal to 65535"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: nothing got registered.
    health = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    assert health == [], f"out-of-range target should not have been registered: {health}"

    # Positive control: the same target id with a valid port succeeds.
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": target_ip, "Port": 8080}])
    ctx.on_cleanup(
        lambda: elbv2.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": target_ip, "Port": 8080}])
    )
    health_after = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    assert len(health_after) == 1
    assert health_after[0]["Target"]["Id"] == target_ip
    assert health_after[0]["Target"]["Port"] == 8080


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _vpc_and_subnet_cidr(ctx):
    """Adopt the run's shared network/subnet if one exists; otherwise create one. A freshly
    provisioned account may have no shared network, and this check must not depend on one."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(SubnetIds=ctx.network().subnet_ids)["Subnets"]
        if subnets:
            return vpc_id, subnets[0]["CidrBlock"]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.201.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-porttg-vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    az_name = next(
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    )
    subnet_cidr = "10.201.1.0/24"
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=subnet_cidr, AvailabilityZone=az_name,
        TagSpecifications=[{
            "ResourceType": "subnet",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-porttg-subnet-")}],
        }],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return vpc_id, subnet_cidr


def _pick_host_ip(cidr: str) -> str:
    network = ipaddress.ip_network(cidr)
    hosts = network.hosts()
    # AWS reserves the first 4 and last 1 address in every VPC subnet (network+1..network+4,
    # and the broadcast address) for its own use; skip well past that reserved band before
    # picking a "real" host address to register as a target.
    for _ in range(10):
        next(hosts)
    return str(next(hosts))


def _unvalidated_client(ctx, service: str):
    """A ctx client with botocore's client-side validation off, so the server judges the port."""
    return ctx.client(
        service, config=Config(parameter_validation=False, retries={"max_attempts": 8, "mode": "standard"})
    )


def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
