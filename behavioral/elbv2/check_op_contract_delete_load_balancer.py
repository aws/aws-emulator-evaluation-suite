"""op-contract-delete-load-balancer."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-load-balancer"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteLoadBalancer removes the LB; a deletion-protected LB rejects delete until unprotected,
    at which point the identical delete call succeeds and the ARN 404s."""
    _, subnet_ids = _default_vpc_and_subnets(ctx)
    if len(subnet_ids) < 2:

        raise AssertionError("need >=2 subnets in distinct AZs to create an ALB")

    elbv2 = ctx.client("elbv2")
    resource_tags = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-alb"}]

    # Success path: a plain (unprotected) ALB deletes cleanly and disappears.
    plain_name = ctx.unique_name("sim2real-alb-pln-")
    plain_arn = elbv2.create_load_balancer(
        Name=plain_name, Subnets=subnet_ids[:2], Type="application", Tags=resource_tags
    )["LoadBalancers"][0]["LoadBalancerArn"]
    resp = elbv2.delete_load_balancer(LoadBalancerArn=plain_arn)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected DeleteLoadBalancer to return 200, got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    code, message = _error(lambda: elbv2.describe_load_balancers(LoadBalancerArns=[plain_arn]))
    # Real AWS's ELBv2 API returns the error type WITHOUT the "Exception" suffix on the wire
    # (unlike the shape name used by the botocore model / docs).
    assert code == "LoadBalancerNotFound", f"LB should be gone, got {code}"
    expected = "One or more load balancers not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Rejection boundary: deletion protection must block DeleteLoadBalancer.
    # ALB names are capped at 32 characters on real AWS; keep the prefix short
    # enough that ctx.unique_name()'s suffix still fits within that limit.
    protected_name = ctx.unique_name("sim2real-alb-prot-")
    protected_arn = elbv2.create_load_balancer(
        Name=protected_name, Subnets=subnet_ids[:2], Type="application", Tags=resource_tags
    )["LoadBalancers"][0]["LoadBalancerArn"]

    def _teardown_protected():
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[protected_arn])
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "LoadBalancerNotFound":
                return
            raise
        elbv2.modify_load_balancer_attributes(
            LoadBalancerArn=protected_arn,
            Attributes=[{"Key": "deletion_protection.enabled", "Value": "false"}],
        )
        elbv2.delete_load_balancer(LoadBalancerArn=protected_arn)

    ctx.on_cleanup(_teardown_protected)

    elbv2.modify_load_balancer_attributes(
        LoadBalancerArn=protected_arn,
        Attributes=[{"Key": "deletion_protection.enabled", "Value": "true"}],
    )
    attrs = {
        a["Key"]: a["Value"]
        for a in elbv2.describe_load_balancer_attributes(LoadBalancerArn=protected_arn)["Attributes"]
    }
    assert attrs.get("deletion_protection.enabled") == "true", (
        f"expected deletion_protection.enabled to read back true, got {attrs.get('deletion_protection.enabled')!r}"
    )

    code, message = _error(lambda: elbv2.delete_load_balancer(LoadBalancerArn=protected_arn))
    # Real AWS's ELBv2 API returns the error type WITHOUT the "Exception" suffix on the wire
    # (unlike the shape name used by the botocore model / docs).
    assert code == "OperationNotPermitted", f"expected deletion-protection rejection, got {code}"
    expected = (
        f"Load balancer '{protected_arn}' cannot be deleted because deletion protection is enabled"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent: the rejected delete must not have removed the LB.
    still_there = elbv2.describe_load_balancers(LoadBalancerArns=[protected_arn])["LoadBalancers"]
    assert still_there and still_there[0]["LoadBalancerArn"] == protected_arn, (
        f"LB should still exist after the rejected delete, got {still_there!r}"
    )

    # Restore: disabling protection must let the identical delete call succeed.
    elbv2.modify_load_balancer_attributes(
        LoadBalancerArn=protected_arn,
        Attributes=[{"Key": "deletion_protection.enabled", "Value": "false"}],
    )
    resp2 = elbv2.delete_load_balancer(LoadBalancerArn=protected_arn)
    assert resp2["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected the identical DeleteLoadBalancer call to succeed after restore, "
        f"got {resp2['ResponseMetadata']['HTTPStatusCode']}"
    )
    code2, message2 = _error(lambda: elbv2.describe_load_balancers(LoadBalancerArns=[protected_arn]))
    assert code2 == "LoadBalancerNotFound", f"LB should be gone after restore+delete, got {code2}"
    expected2 = "One or more load balancers not found"
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _default_vpc_and_subnets(ctx):

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    return vpc_id, list(by_az.values())


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
