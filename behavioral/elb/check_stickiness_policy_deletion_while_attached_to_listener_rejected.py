"""stickiness-policy-deletion-while-attached-to-listener-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stickiness-policy-deletion-while-attached-to-listener-rejected"
GROUP = 'rejection'
SERVICES = ['elb']

# ===== helpers =====
_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _teardown(fn, *gone_codes):
    """Run one teardown call; only the resource's not-found codes count as already deleted."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in gone_codes:
            raise


_ELB_GONE = ("LoadBalancerNotFound", "ListenerNotFound", "PolicyNotFound", "InvalidInstance", "SubnetNotFound",
             "InvalidAssociationID.NotFound")


def _safe(fn):
    """A cleanup step DeleteLoadBalancer also covers: done once the load balancer or the item is gone."""
    return lambda: _teardown(fn, *_ELB_GONE)


def _error(fn):
    """The AWS error code and message `fn` raises; raises if the call succeeds, so accepting
    input AWS rejects is reported as such rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"the call real AWS rejects SUCCEEDED here, returning {str(result)[:300]!r}"
    )


def _internal_network(ctx, n=2):
    """Own VPC and one subnet per availability zone, tagged at creation and independent
    of a default VPC. No internet gateway: nothing here sends a data-plane request, so the load
    balancer is internal."""
    ec2 = ctx.client("ec2")
    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(azs) >= n, f"{ctx.region} has {len(azs)} available zones {azs!r}, need {n}"
    vpc_id = ec2.create_vpc(
        CidrBlock="10.87.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": list(_TAGS)}],
    )["Vpc"]["VpcId"]

    def _drop_vpc():
        _teardown(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound")

    ctx.on_cleanup(_drop_vpc)
    subnet_ids = []
    for i, az in enumerate(azs[:n]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.87.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": list(_TAGS)}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)

        def _drop_subnet(s=subnet_id):
            _teardown(lambda: _delete_net(ec2, "delete_subnet", SubnetId=s), "InvalidSubnetID.NotFound")

        ctx.on_cleanup(_drop_subnet)
    return vpc_id, subnet_ids, azs[:n]


def _sg(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real classic-elb control-plane check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]

    def _drop_sg():
        _teardown(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id), "InvalidGroup.NotFound")

    ctx.on_cleanup(_drop_sg)
    return sg_id


def _create_classic_lb(ctx, subnet_ids, sg_id):
    """Billable resource: the waited teardown is registered AT CREATION (cleanups run LIFO)."""
    elb = ctx.client("elb")
    lb_name = ctx.unique_name("sim2real-clb-")  # 25 chars; the API ceiling is 32
    created = elb.create_load_balancer(
        LoadBalancerName=lb_name,
        Listeners=[{"Protocol": "HTTP", "LoadBalancerPort": 80,
                    "InstanceProtocol": "HTTP", "InstancePort": 80}],
        Subnets=list(subnet_ids), SecurityGroups=[sg_id], Scheme="internal",
        Tags=[{"Key": "sim2real", "Value": CHECK[:64]}],
    )

    def _drop_lb():
        _teardown(lambda: elb.delete_load_balancer(LoadBalancerName=lb_name), "LoadBalancerNotFound")
        # DeleteLoadBalancer returns before the ENIs are released: poll the name out of Describe
        # before the network deletes behind this one run.
        deadline = time.monotonic() + 60
        while True:
            try:
                elb.describe_load_balancers(LoadBalancerNames=[lb_name])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(f"load balancer {lb_name} still described 60 s after DeleteLoadBalancer")
            time.sleep(2)

    ctx.on_cleanup(_drop_lb)
    return lb_name


def _policy_names(ctx, lb_name):
    """Every policy on this load balancer, over the whole reply. Scoped to the load balancer this
    check created, so the assertion cannot be disturbed by a sibling run in the same account."""
    described = ctx.client("elb").describe_load_balancer_policies(LoadBalancerName=lb_name)
    return sorted(p["PolicyName"] for p in described["PolicyDescriptions"])


def _listener_policies(ctx, lb_name, port=80):
    described = ctx.client("elb").describe_load_balancers(
        LoadBalancerNames=[lb_name])["LoadBalancerDescriptions"][0]
    for desc in described["ListenerDescriptions"]:
        if desc["Listener"]["LoadBalancerPort"] == port:
            return list(desc["PolicyNames"])
    raise AssertionError(
        f"load balancer {lb_name} has no listener on port {port}: "
        f"{[d['Listener'] for d in described['ListenerDescriptions']]!r}"
    )


# ===== end helpers =====


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "cap:c5", "plane:control")
def run(ctx) -> None:
    """DeleteLoadBalancerPolicy is rejected with InvalidConfigurationRequest while a listener still
    references the stickiness policy, the policy survives intact, and the identical delete succeeds
    once SetLoadBalancerPoliciesOfListener detaches it."""
    elb = ctx.client("elb")
    vpc_id, subnet_ids, _azs = _internal_network(ctx)
    sg_id = _sg(ctx, vpc_id)
    lb_name = _create_classic_lb(ctx, subnet_ids, sg_id)

    policy = ctx.unique_name("sim2real-sticky-")
    elb.create_lb_cookie_stickiness_policy(
        LoadBalancerName=lb_name, PolicyName=policy, CookieExpirationPeriod=120)
    ctx.on_cleanup(_safe(lambda: elb.delete_load_balancer_policy(
        LoadBalancerName=lb_name, PolicyName=policy)))
    assert _policy_names(ctx, lb_name) == [policy], (
        f"after CreateLBCookieStickinessPolicy the load balancer carries policies "
        f"{_policy_names(ctx, lb_name)!r}, expected exactly [{policy!r}]"
    )
    described = elb.describe_load_balancer_policies(
        LoadBalancerName=lb_name)["PolicyDescriptions"][0]
    assert described["PolicyTypeName"] == "LBCookieStickinessPolicyType", (
        f"the created policy has type {described['PolicyTypeName']!r}, expected "
        f"LBCookieStickinessPolicyType"
    )
    attributes = {a["AttributeName"]: a["AttributeValue"]
                  for a in described["PolicyAttributeDescriptions"]}
    assert attributes == {"CookieExpirationPeriod": "120"}, (
        f"the policy's attributes read back as {attributes!r}, expected the "
        f"CookieExpirationPeriod 120 that created it — as a STRING, which is how this API "
        f"represents policy attribute values"
    )

    # Establish the one thing that makes the delete illegal: a listener referencing the policy.
    elb.set_load_balancer_policies_of_listener(
        LoadBalancerName=lb_name, LoadBalancerPort=80, PolicyNames=[policy])
    ctx.on_cleanup(_safe(lambda: elb.set_load_balancer_policies_of_listener(
        LoadBalancerName=lb_name, LoadBalancerPort=80, PolicyNames=[])))
    assert _listener_policies(ctx, lb_name) == [policy], (
        f"the listener on port 80 references {_listener_policies(ctx, lb_name)!r}, expected "
        f"[{policy!r}]"
    )

    code, message = _error(lambda: elb.delete_load_balancer_policy(
        LoadBalancerName=lb_name, PolicyName=policy))
    assert code == "InvalidConfigurationRequest", (
        f"deleting a policy a listener still references failed with {code!r}, expected "
        f"InvalidConfigurationRequest"
    )
    expected = (
        f"You cannot delete policy [{policy}] since it is enabled or referred by other enabled "
        f"policy."
    )
    assert message == expected, (
        f"deleting a policy a listener still references failed with message {message!r}, "
        f"expected {expected!r}"
    )

    # EFFECT ABSENT: the refused delete removed nothing, from the policy or from the reference.
    assert _policy_names(ctx, lb_name) == [policy], (
        f"after the refused delete the load balancer carries policies "
        f"{_policy_names(ctx, lb_name)!r}, expected the policy to survive intact"
    )
    assert _listener_policies(ctx, lb_name) == [policy], (
        f"after the refused delete the listener references "
        f"{_listener_policies(ctx, lb_name)!r}, expected [{policy!r}] — a refused delete must "
        f"not strip the reference either"
    )

    # POSITIVE CONTROL: detach the reference and the IDENTICAL delete now succeeds, so the
    # refusal is attributable to the reference alone.
    elb.set_load_balancer_policies_of_listener(
        LoadBalancerName=lb_name, LoadBalancerPort=80, PolicyNames=[])
    assert _listener_policies(ctx, lb_name) == [], (
        f"after detaching, the listener still references "
        f"{_listener_policies(ctx, lb_name)!r}, expected no policies"
    )
    elb.delete_load_balancer_policy(LoadBalancerName=lb_name, PolicyName=policy)
    assert _policy_names(ctx, lb_name) == [], (
        f"after the accepted delete the load balancer still carries "
        f"{_policy_names(ctx, lb_name)!r}, expected no policies"
    )


# EC2 network teardown: a resource in this VPC deletes asynchronously and leaves its ENIs behind for a
# while, so each subnet / security group / VPC delete waits for them and retries DependencyViolation
# to one deadline shared by all of the check's network deletes, then raises naming the ENIs left.
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
        _time.sleep(2)
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
        _time.sleep(2)


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
