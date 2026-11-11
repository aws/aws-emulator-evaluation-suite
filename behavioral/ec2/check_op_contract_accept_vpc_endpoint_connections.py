"""op-contract-acceptVpcEndpointConnections."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-acceptVpcEndpointConnections"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AcceptVpcEndpointConnections on an unowned service id fails
    InvalidVpcEndpointServiceId.NotFound with its exact message with and without DryRun; on an owned
    NLB-backed service DryRun fails DryRunOperation and the accept makes the connection available.
    """
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")

    # --- negative leg: a well-formed but unowned service ID never reaches DryRun ---
    fake_service_id = "vpce-svc-0123456789abcdef0"
    fake_endpoint_id = "vpce-0123456789abcdef0"

    info = _error_info(
        lambda: ec2.accept_vpc_endpoint_connections(
            ServiceId=fake_service_id, VpcEndpointIds=[fake_endpoint_id], DryRun=True
        )
    )
    assert info["code"] == "InvalidVpcEndpointServiceId.NotFound", (
        f"expected InvalidVpcEndpointServiceId.NotFound, got {info['code']!r}"
    )
    not_found_message = f"The VpcEndpointService Id '{fake_service_id}' does not exist"
    assert info["message"] == not_found_message, (
        f"expected message {not_found_message!r}, got {info['message']!r}"
    )

    info2 = _error_info(
        lambda: ec2.accept_vpc_endpoint_connections(
            ServiceId=fake_service_id, VpcEndpointIds=[fake_endpoint_id]
        )
    )
    assert info2["code"] == "InvalidVpcEndpointServiceId.NotFound", (
        f"expected InvalidVpcEndpointServiceId.NotFound, got {info2['code']!r}"
    )
    assert info2["message"] == not_found_message, (
        f"expected message {not_found_message!r}, got {info2['message']!r}"
    )

    # --- positive control: a real, owned service with a real pending connection ---
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"][0]["ZoneName"]

    # The provider and consumer sides share the run's network VPC (AWS does not require them to
    # differ), in two distinct subnets, different AZs when available.
    default_vpc = _default_vpc(ec2, ctx=ctx)
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])[
            "AvailabilityZones"
        ]
    ]
    provider_subnet = _default_subnet(ec2, default_vpc, az, ctx=ctx)

    consumer_az = next((z for z in azs if z != az), az)
    consumer_subnet = _default_subnet(ec2, default_vpc, consumer_az, ctx=ctx)

    # A VPC endpoint service only supports the AZs backed by the network load balancer's own
    # subnets, so register the NLB across both the provider's and the consumer's AZ (when they
    # differ) so the resulting endpoint service actually supports the consumer's AZ too.
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
        TagSpecifications=[
            {
                "ResourceType": "vpc-endpoint-service",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vpce-svc-")}],
            }
        ],
    )["ServiceConfiguration"]
    real_service_id = svc["ServiceId"]
    real_service_name = svc["ServiceName"]
    ctx.on_cleanup(lambda: _delete_endpoint_service(ec2, real_service_id))

    default_sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [default_vpc]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]

    real_vpce_id = ec2.create_vpc_endpoint(
        VpcEndpointType="Interface",
        VpcId=default_vpc,
        ServiceName=real_service_name,
        SubnetIds=[consumer_subnet],
        SecurityGroupIds=[default_sg],
        TagSpecifications=[
            {
                "ResourceType": "vpc-endpoint",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vpce-")}],
            }
        ],
    )["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: _delete_vpc_endpoint(ec2, real_vpce_id))

    _poll_until(
        lambda: _connection_state(ec2, real_service_id, real_vpce_id),
        lambda s: s == "pendingAcceptance",
        timeout_s=120,
        interval_s=5,
    )

    # Ownership passes for the real, owned service -- so DryRun is now reached and reported,
    # unlike the unowned-service case above where it never gets that far.
    real = _error_info(
        lambda: ec2.accept_vpc_endpoint_connections(
            ServiceId=real_service_id, VpcEndpointIds=[real_vpce_id], DryRun=True
        )
    )
    assert real["code"] == "DryRunOperation", f"expected DryRunOperation, got {real['code']!r}"
    assert real["message"] == DRY_RUN_MESSAGE, (
        f"expected message {DRY_RUN_MESSAGE!r}, got {real['message']!r}"
    )

    # The real accept succeeds and DescribeVpcEndpointConnections shows the connection
    # 'available'. The accept can race the endpoint's provisioning as a per-item
    # 'Unavailable' error, so only that error is retried, within the same window.
    unsuccessful = _accept_until_provisioned(ec2, real_service_id, real_vpce_id, timeout_s=60)
    assert unsuccessful == [], f"unexpected failures: {unsuccessful}"

    final_state = _poll_until(
        lambda: _connection_state(ec2, real_service_id, real_vpce_id),
        lambda s: s == "available",
        timeout_s=60,
        interval_s=3,
    )
    assert final_state == "available", f"expected 'available', got {final_state!r}"


def _error_info(fn):
    """Call fn(); return its botocore error. An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses is not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {"code": err["Code"], "message": err.get("Message")}
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _accept_until_provisioned(ec2, service_id, vpce_id, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    unsuccessful = None
    while True:
        resp = ec2.accept_vpc_endpoint_connections(ServiceId=service_id, VpcEndpointIds=[vpce_id])
        unsuccessful = resp.get("Unsuccessful", [])
        still_provisioning = unsuccessful and all(
            item.get("Error", {}).get("Code") == "Unavailable" for item in unsuccessful
        )
        if not still_provisioning or time.monotonic() >= deadline:
            return unsuccessful
        time.sleep(interval_s)


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
