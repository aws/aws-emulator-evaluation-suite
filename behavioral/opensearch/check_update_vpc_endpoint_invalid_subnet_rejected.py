"""update-vpc-endpoint-invalid-subnet-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-vpc-endpoint-invalid-subnet-rejected"
GROUP = "negative-classes"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateVpcEndpoint with a subnet from a different VPC than its security group raises
    ValidationException and leaves the endpoint's subnet unchanged; a same-VPC update succeeds.
    """
    ec2 = ctx.client("ec2")
    opensearch = ctx.client("opensearch")

    vpc_a = _create_vpc(ctx, ec2, "10.30.0.0/16")
    subnet_a1 = _create_subnet(ctx, ec2, vpc_a, "10.30.1.0/24")
    subnet_a2 = _create_subnet(ctx, ec2, vpc_a, "10.30.2.0/24")
    sg_a = _create_security_group(ctx, ec2, vpc_a, ctx.unique_name("sim2real-sg-"))

    vpc_b = _create_vpc(ctx, ec2, "10.40.0.0/16")
    subnet_b = _create_subnet(ctx, ec2, vpc_b, "10.40.1.0/24")

    domain_name = _domain_name(ctx, "vpe")
    _create_vpc_domain(ctx, opensearch, domain_name, subnet_a1, sg_a)
    domain_arn = _wait_domain_active(ctx, opensearch, domain_name)["ARN"]

    endpoint = opensearch.create_vpc_endpoint(
        DomainArn=domain_arn,
        VpcOptions={"SubnetIds": [subnet_a1], "SecurityGroupIds": [sg_a]},
    )["VpcEndpoint"]
    endpoint_id = endpoint["VpcEndpointId"]
    ctx.on_cleanup(lambda: _delete_vpc_endpoint_and_wait(ctx, opensearch, endpoint_id))
    _wait_vpc_endpoint_status(ctx, opensearch, endpoint_id, {"ACTIVE"})

    def _break() -> None:
        opensearch.update_vpc_endpoint(
            VpcEndpointId=endpoint_id,
            VpcOptions={"SubnetIds": [subnet_b], "SecurityGroupIds": [sg_a]},
        )

    code = _error_code(_break)
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"

    # Effect absent: the endpoint still points at the original VPC-A subnet.
    described = opensearch.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]
    assert described["VpcOptions"]["SubnetIds"] == [subnet_a1], (
        f"expected rejected update to leave subnet unchanged at {[subnet_a1]!r}, "
        f"got {described['VpcOptions']['SubnetIds']!r}"
    )

    # Positive control: a subnet from the SAME VPC as the security group succeeds.
    opensearch.update_vpc_endpoint(
        VpcEndpointId=endpoint_id,
        VpcOptions={"SubnetIds": [subnet_a2], "SecurityGroupIds": [sg_a]},
    )
    _wait_vpc_endpoint_status(ctx, opensearch, endpoint_id, {"ACTIVE"})
    described_after = opensearch.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]
    assert described_after["VpcOptions"]["SubnetIds"] == [subnet_a2], (
        f"expected legitimate same-VPC update to apply subnet {[subnet_a2]!r}, "
        f"got {described_after['VpcOptions']['SubnetIds']!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _domain_name(ctx: Any, tag: str) -> str:
    return ctx.unique_name(f"sim2real-{tag}-")[:28].rstrip("-")


def _create_vpc(ctx: Any, ec2: Any, cidr: str) -> str:
    vpc_id = ec2.create_vpc(CidrBlock=cidr)["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, vpc_id, f"vpc {vpc_id}", lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-vpc-")}])
    return vpc_id


def _create_subnet(ctx: Any, ec2: Any, vpc_id: str, cidr: str) -> str:
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=cidr)["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, vpc_id, f"subnet {subnet_id}", lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-subnet-")}])
    return subnet_id


def _create_security_group(ctx: Any, ec2: Any, vpc_id: str, name: str) -> str:
    sg_id = ec2.create_security_group(
        GroupName=name, Description="sim2real opensearch behavioral check", VpcId=vpc_id
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, vpc_id, f"sg {sg_id}", lambda: ec2.delete_security_group(GroupId=sg_id)))
    return sg_id


def _create_vpc_domain(ctx: Any, client: Any, domain_name: str, subnet_id: str, sg_id: str) -> None:
    client.create_domain(
        DomainName=domain_name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        VPCOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
    )
    ctx.on_cleanup(lambda: _delete_domain(ctx, client, domain_name))


def _delete_domain(ctx: Any, client: Any, domain_name: str) -> None:
    """Issue the delete and return; `_delete_net` waits for the domain's ENIs to leave the VPC."""
    try:
        client.delete_domain(DomainName=domain_name)
    except Exception as exc:
        if _error_code_from_exc(exc) != "ResourceNotFoundException":
            raise


def _wait_domain_active(ctx: Any, client: Any, domain_name: str, timeout_s: float = 1500.0) -> dict:
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while True:
        status = client.describe_domain(DomainName=domain_name)["DomainStatus"]
        last = status
        if status.get("Created") and not status.get("Processing") and status.get("Endpoints"):
            return status
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} active: the run budget ended first; not graded")
    raise AssertionError(f"domain {domain_name} never became active: {last}")


def _wait_vpc_endpoint_status(ctx: Any, client: Any, endpoint_id: str, terminal: set, timeout_s: float = 600.0) -> None:
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while True:
        described = client.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]
        last = described["Status"]
        if last in terminal:
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"vpc endpoint {endpoint_id} {terminal}: the run budget ended first; not graded")
    raise AssertionError(f"vpc endpoint {endpoint_id} never reached {terminal}: {last}")


def _delete_vpc_endpoint_and_wait(ctx: Any, client: Any, endpoint_id: str, timeout_s: float = 180.0) -> None:
    try:
        client.delete_vpc_endpoint(VpcEndpointId=endpoint_id)
    except Exception as exc:
        if _error_code_from_exc(exc) != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        described = client.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"]
        if not described or described[0]["Status"] not in ("DELETING",):
            return
        time.sleep(2.0)


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _error_code(fn) -> str | None:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return _error_code_from_exc(exc)
    return None


# The OpenSearch domain and VPC endpoint delete asynchronously and keep ENIs in the VPC for a
# while, so an immediate DeleteSecurityGroup / DeleteSubnet / DeleteVpc fails with
# DependencyViolation. Each network delete waits (bounded) for the VPC to hold no ENIs, retries
# DependencyViolation in the same window, then raises naming what still holds the VPC.
# The window is shared by all of one VPC's network deletes.
_NET_TEARDOWN_S = 660.0
_NET_DEADLINES: dict = {}


def _delete_net(ec2, vpc_id, label, delete) -> None:
    deadline = _NET_DEADLINES.setdefault(vpc_id, time.monotonic() + _NET_TEARDOWN_S)
    while _vpc_enis(ec2, vpc_id) and time.monotonic() < deadline:
        time.sleep(2)
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise RuntimeError(
                    f"{label}: {code}; ENIs still in {vpc_id}: {_vpc_enis(ec2, vpc_id)}"
                ) from exc
        time.sleep(2)


def _vpc_enis(ec2, vpc_id) -> list:
    try:
        enis = ec2.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    except ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [
        f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}"
        for e in enis["NetworkInterfaces"]
    ]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
