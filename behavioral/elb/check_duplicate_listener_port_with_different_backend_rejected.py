"""duplicate-listener-port-with-different-backend-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-listener-port-with-different-backend-rejected"
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
        CidrBlock="10.90.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": list(_TAGS)}],
    )["Vpc"]["VpcId"]

    def _drop_vpc():
        _teardown(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound")

    ctx.on_cleanup(_drop_vpc)
    subnet_ids = []
    for i, az in enumerate(azs[:n]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.90.{i}.0/24", AvailabilityZone=az,
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
    elb.create_load_balancer(
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


def _listeners(ctx, lb_name):
    described = ctx.client("elb").describe_load_balancers(
        LoadBalancerNames=[lb_name])["LoadBalancerDescriptions"][0]
    return sorted((d["Listener"] for d in described["ListenerDescriptions"]),
                  key=lambda listener: listener["LoadBalancerPort"])


# ===== end helpers =====


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:representation",
    "cap:c1",
    "cap:c5",
    "plane:control",
)
def run(ctx) -> None:
    """CreateLoadBalancerListeners returns 200 and changes nothing for a listener identical to an
    existing one, and rejects one differing only in its backend port with DuplicateListener,
    leaving the existing listener's backend untouched."""
    elb = ctx.client("elb")
    vpc_id, subnet_ids, _azs = _internal_network(ctx)
    sg_id = _sg(ctx, vpc_id)
    lb_name = _create_classic_lb(ctx, subnet_ids, sg_id)

    http_80 = {"Protocol": "HTTP", "LoadBalancerPort": 80,
               "InstanceProtocol": "HTTP", "InstancePort": 80}
    before = _listeners(ctx, lb_name)
    assert before == [http_80], (
        f"the load balancer carries listeners {before!r}, expected exactly [{http_80!r}]"
    )

    # POSITIVE CONTROL: the byte-identical listener is accepted, and is not duplicated.
    identical = elb.create_load_balancer_listeners(
        LoadBalancerName=lb_name, Listeners=[dict(http_80)])
    assert identical["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"re-creating the identical listener returned HTTP "
        f"{identical['ResponseMetadata']['HTTPStatusCode']}, expected 200"
    )
    assert _listeners(ctx, lb_name) == [http_80], (
        f"after re-creating the identical listener the load balancer carries "
        f"{_listeners(ctx, lb_name)!r}, expected the single unchanged {http_80!r}"
    )

    # Break exactly one field: the backend port behind the SAME front-end port.
    code, message = _error(lambda: elb.create_load_balancer_listeners(
        LoadBalancerName=lb_name,
        Listeners=[{"Protocol": "HTTP", "LoadBalancerPort": 80,
                    "InstanceProtocol": "HTTP", "InstancePort": 8080}]))
    assert code == "DuplicateListener", (
        f"creating a listener on the occupied port 80 with a different backend port failed with "
        f"{code!r}, expected DuplicateListener"
    )
    expected_message = (
        f"A listener already exists for {lb_name} with LoadBalancerPort 80, but with a different "
        f"InstancePort, Protocol, or SSLCertificateId"
    )
    assert message == expected_message, (
        f"DuplicateListener carried the message {message!r}, expected {expected_message!r}"
    )

    # EFFECT ABSENT: the listener still points at the original backend port.
    after = _listeners(ctx, lb_name)
    assert after == [http_80], (
        f"after the rejected listener the load balancer carries {after!r}, expected the "
        f"unchanged {http_80!r} — the rejected backend port must not have been applied"
    )

    # And a free front-end port takes the very configuration that was just rejected, so the
    # rejection is attributable to the port collision alone.
    http_8081 = {"Protocol": "HTTP", "LoadBalancerPort": 8081,
                 "InstanceProtocol": "HTTP", "InstancePort": 8080}
    elb.create_load_balancer_listeners(LoadBalancerName=lb_name, Listeners=[dict(http_8081)])
    ctx.on_cleanup(lambda: elb.delete_load_balancer_listeners(
        LoadBalancerName=lb_name, LoadBalancerPorts=[8081]))
    assert _listeners(ctx, lb_name) == [http_80, http_8081], (
        f"after adding a listener on a free port the load balancer carries "
        f"{_listeners(ctx, lb_name)!r}, expected {[http_80, http_8081]!r}"
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
