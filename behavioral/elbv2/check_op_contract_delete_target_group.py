"""op-contract-delete-target-group."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-target-group"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTargetGroup removes an unused TG; deleting one still referenced by a listener is
    rejected with ResourceInUse, the TG remains describable, and once the listener's default
    action is repointed away from it the identical delete call succeeds."""
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    if len(subnet_ids) < 2:

        raise AssertionError("need >=2 subnets in distinct AZs to create an ALB")

    elbv2 = ctx.client("elbv2")

    # Success path: an unreferenced target group deletes cleanly.
    standalone_tg = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-tg-solo-"), Protocol="HTTP", Port=80, VpcId=vpc_id,
        TargetType="instance",
    )["TargetGroups"][0]
    resp = elbv2.delete_target_group(TargetGroupArn=standalone_tg["TargetGroupArn"])
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    code, message = _error(
        lambda: elbv2.describe_target_groups(TargetGroupArns=[standalone_tg["TargetGroupArn"]])
    )
    # Real AWS's ELBv2 API returns the error type WITHOUT the "Exception" suffix on the wire
    # (unlike the shape name used by the botocore model / docs).
    assert code == "TargetGroupNotFound", f"TG should be gone, got {code}"
    expected = "One or more target groups not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Rejection boundary: a TG referenced by a listener's default action cannot be deleted.
    lb = _create_alb(ctx, subnet_ids)
    referenced_tg = _create_tg(ctx, vpc_id, name=ctx.unique_name("sim2real-tg-ref-"))
    listener = _create_listener(ctx, lb["LoadBalancerArn"], referenced_tg["TargetGroupArn"])

    code, message = _error(lambda: elbv2.delete_target_group(TargetGroupArn=referenced_tg["TargetGroupArn"]))
    assert code == "ResourceInUse", f"expected in-use rejection, got {code}"
    expected = f"Target group '{referenced_tg['TargetGroupArn']}' is currently in use by a listener or a rule"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent: the rejected delete left the target group untouched.
    still_there = elbv2.describe_target_groups(TargetGroupArns=[referenced_tg["TargetGroupArn"]])["TargetGroups"]
    assert still_there and still_there[0]["TargetGroupArn"] == referenced_tg["TargetGroupArn"], (
        "TG must still be describable after its delete was rejected"
    )

    # Restore: repoint the listener's default action so the TG is no longer referenced.
    elbv2.modify_listener(
        ListenerArn=listener["ListenerArn"],
        DefaultActions=[{"Type": "fixed-response", "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain"}}],
    )

    # The identical delete call now succeeds, and an independent read confirms it is gone.
    resp = elbv2.delete_target_group(TargetGroupArn=referenced_tg["TargetGroupArn"])
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    code, message = _error(
        lambda: elbv2.describe_target_groups(TargetGroupArns=[referenced_tg["TargetGroupArn"]])
    )
    assert code == "TargetGroupNotFound", f"TG should be gone after restore, got {code}"
    expected = "One or more target groups not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-alb-")
    resp = elbv2.create_load_balancer(Name=name, Subnets=subnet_ids[:2], Type="application")
    lb = resp["LoadBalancers"][0]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb["LoadBalancerArn"]))
    return lb


def _create_tg(ctx, vpc_id, name=None, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-tg-")
    params = dict(Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance")
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg["TargetGroupArn"]))
    return tg


def _create_listener(ctx, lb_arn, tg_arn, port=80):
    elbv2 = ctx.client("elbv2")
    resp = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )
    listener = resp["Listeners"][0]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener["ListenerArn"]))
    return listener



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
