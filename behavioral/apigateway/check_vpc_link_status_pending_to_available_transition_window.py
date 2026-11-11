"""vpc-link-status-pending-to-available-transition-window."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-link-status-pending-to-available-transition-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created VpcLink starts in PENDING, as CreateVpcLink reports, rather than being
    immediately AVAILABLE, and transitions to AVAILABLE within a bounded window."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    apigw = ctx.client("apigateway")

    vpc = ec2.create_vpc(
        CidrBlock="10.221.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-apigw-vpc-")}]}],
    )
    vpc_id = vpc["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_while_in_use(
        lambda: ec2.delete_vpc(VpcId=vpc_id), "DependencyViolation", "InvalidVpcID.NotFound"
    ))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    az_names = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.221.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-apigw-subnet{i}-")}]}
            ],
        )
        sid = subnet["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_while_in_use(
            lambda: ec2.delete_subnet(SubnetId=sid), "DependencyViolation", "InvalidSubnetID.NotFound"
        ))
    ec2.get_waiter("subnet_available").wait(SubnetIds=subnet_ids, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    nlb_name = ctx.unique_name("sim2real-apigw-nlb-")
    nlb = elbv2.create_load_balancer(
        Name=nlb_name,
        Subnets=subnet_ids,
        Scheme="internal",
        Type="network",
        Tags=[{"Key": "Name", "Value": nlb_name}],
    )
    nlb_arn = nlb["LoadBalancers"][0]["LoadBalancerArn"]

    def _delete_nlb_and_wait() -> None:
        # The NLB stays associated with the VpcLink until the link's own deletion settles.
        _delete_while_in_use(
            lambda: elbv2.delete_load_balancer(LoadBalancerArn=nlb_arn), "ResourceInUse", "LoadBalancerNotFound"
        )
        elbv2.get_waiter("load_balancers_deleted").wait(LoadBalancerArns=[nlb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_delete_nlb_and_wait)

    # CreateVpcLink against a not-yet-active NLB drives the link straight to FAILED ("NLB is not
    # in active state") instead of exercising the PENDING -> AVAILABLE window this check targets.
    elbv2.get_waiter("load_balancer_available").wait(LoadBalancerArns=[nlb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    link = apigw.create_vpc_link(name=ctx.unique_name("sim2real-apigw-vpclink-"), targetArns=[nlb_arn])
    link_id = link["id"]
    ctx.on_cleanup(lambda: apigw.delete_vpc_link(vpcLinkId=link_id))

    assert link["status"] == "PENDING", f"expected initial VpcLink status PENDING, got {link['status']}"

    final_status = None
    left = ctx.time_left()
    # up to 15 min for real NLB-backed VpcLink provisioning
    deadline = time.monotonic() + (900 if left is None else min(900, left))
    while time.monotonic() < deadline:
        cur = apigw.get_vpc_link(vpcLinkId=link_id)
        if cur["status"] == "AVAILABLE":
            final_status = "AVAILABLE"
            break
        elif cur["status"] == "FAILED":
            raise AssertionError(f"VpcLink entered FAILED status: {cur.get('statusMessage')}")
        assert cur["status"] == "PENDING", f"expected VpcLink PENDING before AVAILABLE, got {cur['status']}"
        time.sleep(2)

    assert final_status == "AVAILABLE", "VpcLink never reached AVAILABLE within the expected window"


def _delete_while_in_use(delete, in_use_code: str, gone_code: str, timeout_s: float = 600.0) -> None:
    """Teardown: retry ``delete`` while AWS still reports the resource in use; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == gone_code:
                return
            if code != in_use_code or time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
