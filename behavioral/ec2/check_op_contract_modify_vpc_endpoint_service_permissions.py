"""op-contract-modify-vpc-endpoint-service-permissions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-modify-vpc-endpoint-service-permissions"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVpcEndpointServicePermissions: success adds and then removes an
    allowed principal, observed via DescribeVpcEndpointServicePermissions;
    DryRun is rejected with DryRunOperation."""
    ec2 = ctx.client("ec2")

    svc = _create_nlb_backed_service(ctx)
    initial_principals = _describe_permissions(ec2, svc["service_id"])
    assert initial_principals == [], initial_principals

    # error boundary: DryRun must reject without mutating the permission set.
    err, err_message = _error(
        lambda: ec2.modify_vpc_endpoint_service_permissions(
            ServiceId=svc["service_id"], AddAllowedPrincipals=["*"], DryRun=True
        )
    )
    assert err == "DryRunOperation", err
    assert err_message == "Request would have succeeded, but DryRun flag is set.", err_message
    after_dry_run = _describe_permissions(ec2, svc["service_id"])
    assert after_dry_run == [], f"DryRun mutated the permission set: {after_dry_run}"

    # success path: allow every principal, then revoke it again.
    added = ec2.modify_vpc_endpoint_service_permissions(ServiceId=svc["service_id"], AddAllowedPrincipals=["*"])
    # Real AWS names the boolean result field "ReturnValue" (not "Return") and
    # echoes the changed principals under "AddedPrincipals" (not
    # "AddedPrincipalSet") for this operation.
    assert added["ReturnValue"] is True, f"expected ReturnValue True, got {added.get('ReturnValue')}"
    assert [p["Principal"] for p in added["AddedPrincipals"]] == ["*"], added

    after_add = _describe_permissions(ec2, svc["service_id"])
    assert after_add == ["*"], after_add

    removed = ec2.modify_vpc_endpoint_service_permissions(ServiceId=svc["service_id"], RemoveAllowedPrincipals=["*"])
    assert removed["ReturnValue"] is True, f"expected ReturnValue True, got {removed.get('ReturnValue')}"

    after_remove = _poll_until(
        lambda: _describe_permissions(ec2, svc["service_id"]),
        lambda principals: principals == [],
        timeout_s=60,
        interval_s=5,
    )
    assert after_remove == [], after_remove


# ===== helpers =====
def _tag_spec(ctx, resource_type, prefix):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}]}]


def _short_name(ctx, prefix):
    name = ctx.unique_name(f"{prefix}-")[:32]
    while name.endswith("-"):
        name = name[:-1]
    return name


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _describe_permissions(ec2, service_id):
    resp = ec2.describe_vpc_endpoint_service_permissions(ServiceId=service_id)
    return [p["Principal"] for p in resp.get("AllowedPrincipals", [])]


def _nlb_exists(elbv2, nlb_arn):
    try:
        elbv2.describe_load_balancers(LoadBalancerArns=[nlb_arn])
        return True
    except elbv2.exceptions.LoadBalancerNotFoundException:
        return False


def _wait_for_nlb_active(elbv2, nlb_arn, timeout_s=180.0, interval_s=10.0):
    def _describe():
        resp = elbv2.describe_load_balancers(LoadBalancerArns=[nlb_arn])
        lbs = resp.get("LoadBalancers", [])
        return lbs[0] if lbs else None

    return _poll_until(
        _describe,
        lambda lb: lb is not None and lb.get("State", {}).get("Code") == "active",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _create_nlb_backed_service(ctx):
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")

    vpc_id = ec2.create_vpc(CidrBlock="10.213.0.0/16", TagSpecifications=_tag_spec(ctx, "vpc", "svc-vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, vpc_id, f"vpc {vpc_id}", lambda: ec2.delete_vpc(VpcId=vpc_id)))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.213.1.0/24", TagSpecifications=_tag_spec(ctx, "subnet", "svc-subnet")
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, vpc_id, f"subnet {subnet_id}", lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    nlb_arn = elbv2.create_load_balancer(
        Name=_short_name(ctx, "sim2realnlb"),
        Type="network",
        Scheme="internal",
        Subnets=[subnet_id],
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-svc-nlb-")}],
    )["LoadBalancers"][0]["LoadBalancerArn"]

    def _cleanup_nlb():
        elbv2.delete_load_balancer(LoadBalancerArn=nlb_arn)
        _poll_until(lambda: _nlb_exists(elbv2, nlb_arn), lambda exists: not exists, timeout_s=180, interval_s=10)

    ctx.on_cleanup(_cleanup_nlb)

    # A freshly created NLB is not immediately usable as a VPC endpoint service
    # backend on real AWS — it starts in "provisioning" and CreateVpcEndpointServiceConfiguration
    # rejects it with InvalidParameter until it reaches "active".
    _wait_for_nlb_active(elbv2, nlb_arn)

    svc = ec2.create_vpc_endpoint_service_configuration(
        NetworkLoadBalancerArns=[nlb_arn],
        AcceptanceRequired=False,
        TagSpecifications=_tag_spec(ctx, "vpc-endpoint-service", "svc-cfg"),
    )["ServiceConfiguration"]
    service_id = svc["ServiceId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoint_service_configurations(ServiceIds=[service_id]))

    return {
        "vpc_id": vpc_id,
        "subnet_id": subnet_id,
        "nlb_arn": nlb_arn,
        "service_id": service_id,
        "service_name": svc["ServiceName"],
    }


# Check-created VPC networking is torn down only once the AWS-managed ENIs inside it are gone.
# Holder here: the internal Network Load Balancer behind the endpoint service (its
# per-subnet ENIs drain only after DeleteLoadBalancer returns and the LB stops describing).
# It deletes ASYNCHRONOUSLY: the delete call returns while its requester-managed ENIs still sit in
# the VPC, and a DeleteSecurityGroup / DeleteSubnet / DeleteVpc issued in that window fails with
# DependencyViolation. So every network delete
# waits (bounded) for the VPC to hold no ENIs, retries DependencyViolation within the SAME window, and
# RAISES a final failure naming what still holds the VPC. The window is
# shared by all of one VPC's network deletes and sized to fit, with the holder cleanups that run
# before it, inside this suite's cleanup budget.
_NET_TEARDOWN_S = 660.0
_NET_DEADLINES: dict = {}


def _delete_net(ec2, vpc_id, label, delete) -> None:
    deadline = _NET_DEADLINES.setdefault(vpc_id, time.monotonic() + _NET_TEARDOWN_S)
    while _vpc_enis(ec2, vpc_id) and time.monotonic() < deadline:
        time.sleep(15)
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
        time.sleep(15)


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
