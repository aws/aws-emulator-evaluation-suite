"""op-contract-reject-vpc-endpoint-connections."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-reject-vpc-endpoint-connections"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RejectVpcEndpointConnections with DryRun fails with DryRunOperation and leaves the connection
    pendingAcceptance; without DryRun it reports no Unsuccessful entries and the connection reaches
    "rejected", which a later AcceptVpcEndpointConnections does not change."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"][0]["ZoneName"]

    # Reuse the account's default VPC for both the provider and consumer sides instead of
    # creating two new VPCs: AWS does not require an endpoint service and its consumer to live in
    # different VPCs, and provisioning fresh VPCs here is an unnecessary assumption of spare VPC
    # quota (real accounts running many checks concurrently can legitimately hit the per-region
    # VPC limit). We still use two distinct subnets (different AZs when available) so the NLB and
    # the interface endpoint sit in genuinely separate subnets.
    default_vpc = _default_vpc(ec2, ctx=ctx)
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])[
            "AvailabilityZones"
        ]
    ]
    provider_subnet = _default_subnet(ec2, default_vpc, az, ctx=ctx)

    consumer_vpc = default_vpc
    consumer_az = next((z for z in azs if z != az), az)
    consumer_subnet = _default_subnet(ec2, default_vpc, consumer_az, ctx=ctx)

    # A VPC endpoint service only supports the AZs backed by the network load balancer's own
    # subnets (verified for real: CreateVpcEndpoint fails with InvalidParameter -- "does not
    # support the availability zone of the subnet" -- when the consumer subnet's AZ isn't one of
    # them). Register the NLB across BOTH the provider's and the consumer's AZ (when they differ)
    # so the resulting endpoint service actually supports the consumer's AZ too.
    nlb_subnets = [provider_subnet]
    if consumer_subnet != provider_subnet:
        nlb_subnets.append(consumer_subnet)

    nlb_name = ctx.unique_name("sim2real-nlb-")[:32]
    nlb_arn = elbv2.create_load_balancer(
        Name=nlb_name,
        Subnets=nlb_subnets,
        Scheme="internal",
        Type="network",
        Tags=[{"Key": "Name", "Value": nlb_name}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_nlb(elbv2, nlb_arn))
    elbv2.get_waiter("load_balancer_available").wait(LoadBalancerArns=[nlb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    svc = ec2.create_vpc_endpoint_service_configuration(
        NetworkLoadBalancerArns=[nlb_arn],
        AcceptanceRequired=True,
        TagSpecifications=_tag_spec(ctx, "vpc-endpoint-service", "svc-cfg"),
    )["ServiceConfiguration"]
    service_id = svc["ServiceId"]
    service_name = svc["ServiceName"]
    ctx.on_cleanup(lambda: _delete_endpoint_service(ec2, service_id))

    # --- consumer side: interface endpoint in the (shared) default VPC ---
    default_sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [consumer_vpc]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]

    vpce_id = ec2.create_vpc_endpoint(
        VpcEndpointType="Interface",
        VpcId=consumer_vpc,
        ServiceName=service_name,
        SubnetIds=[consumer_subnet],
        SecurityGroupIds=[default_sg],
        TagSpecifications=_tag_spec(ctx, "vpc-endpoint", "consumer-vpce"),
    )["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: _delete_vpc_endpoint(ec2, vpce_id))

    _poll_until(
        lambda: _connection_state(ec2, service_id, vpce_id),
        lambda s: s == "pendingAcceptance",
        timeout_s=120,
        interval_s=5,
    )

    # --- error boundary: DryRun on the real pending connection ---
    code, message = _error(
        lambda: ec2.reject_vpc_endpoint_connections(DryRun=True, ServiceId=service_id, VpcEndpointIds=[vpce_id])
    )
    assert (code, message) == ("DryRunOperation", _DRY_RUN_MESSAGE), (
        f"expected DryRunOperation {_DRY_RUN_MESSAGE!r}, got {code!r} {message!r}"
    )

    state_after_dry_run = _connection_state(ec2, service_id, vpce_id)
    assert state_after_dry_run == "pendingAcceptance", (
        f"DryRun must not mutate state, expected 'pendingAcceptance', got {state_after_dry_run!r}"
    )

    # --- success path: reject transitions pendingAcceptance -> rejected ---
    resp = ec2.reject_vpc_endpoint_connections(ServiceId=service_id, VpcEndpointIds=[vpce_id])
    assert resp.get("Unsuccessful", []) == [], f"unexpected failures: {resp.get('Unsuccessful')}"

    final_state = _poll_until(
        lambda: _connection_state(ec2, service_id, vpce_id),
        lambda s: s == "rejected",
        timeout_s=60,
        interval_s=3,
    )
    assert final_state == "rejected", f"expected connection state 'rejected', got {final_state!r}"

    # --- rejection is enforced, not merely recorded: it cannot be un-rejected by accepting it ---
    try:
        ec2.accept_vpc_endpoint_connections(ServiceId=service_id, VpcEndpointIds=[vpce_id])
    except ClientError:
        pass
    state_after_accept_attempt = _connection_state(ec2, service_id, vpce_id)
    assert state_after_accept_attempt == "rejected", (
        f"accepting an already-rejected connection must not change its state, "
        f"got {state_after_accept_attempt!r}"
    )


def _tag_spec(ctx, resource_type, prefix):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}]}]


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. A success raises: an
    accepted call is the strongest signal and must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _connection_state(ec2, service_id, vpce_id):
    resp = ec2.describe_vpc_endpoint_connections(
        Filters=[{"Name": "service-id", "Values": [service_id]}]
    )
    for conn in resp.get("VpcEndpointConnections", []):
        if conn.get("VpcEndpointId") == vpce_id:
            return conn["VpcEndpointState"]
    return "not-found"


def _delete_vpc_endpoint(ec2, vpce_id):
    ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id])


def _delete_endpoint_service(ec2, service_id):
    ec2.delete_vpc_endpoint_service_configurations(ServiceIds=[service_id])


def _delete_nlb(elbv2, nlb_arn):
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=nlb_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise


def _default_vpc(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    return vpcs[0]["VpcId"]


def _default_subnet(ec2, vpc_id, az, *, ctx):
    filters = [{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "availability-zone", "Values": [az]}]
    subnets = ec2.describe_subnets(Filters=filters + [{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    return subnets[0]["SubnetId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
