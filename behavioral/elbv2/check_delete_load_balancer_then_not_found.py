"""delete-load-balancer-then-not-found."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-load-balancer-then-not-found"
GROUP = 'load-balancer-lifecycle'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteLoadBalancer, the ARN must no longer resolve via DescribeLoadBalancers."""

    _net_cache = {}
    elb = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    def _tags_kv():
        return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

    def _retry_throttled(fn, attempts=5):
        delays = [3, 6, 12, 24, 30]
        last_exc = None
        for attempt in range(attempts):
            try:
                return fn()
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code not in _THROTTLE_CODES:
                    raise
                last_exc = exc
                time.sleep(delays[min(attempt, len(delays) - 1)])
        raise last_exc

    def _error(fn):
        """Run ``fn``, which AWS refuses, and return the refusal's (code, message); a throttle
        is retried and an unexpected success raises."""
        delays = [3, 6, 12, 24, 30]
        code, message = "", ""
        for attempt in range(5):
            try:
                fn()
            except ClientError as exc:
                err = exc.response.get("Error", {})
                code, message = err.get("Code", ""), err.get("Message", "")
            else:
                raise AssertionError("expected the call to be refused, but it succeeded")
            if code not in _THROTTLE_CODES:
                return code, message
            time.sleep(delays[attempt])
        return code, message

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    def _setup_network(num_subnets=2):
        if _net_cache:
            return _net_cache["net"]
        default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
        if default_vpcs:
            vpc_id = default_vpcs[0]["VpcId"]
            subnets = ec2.describe_subnets(Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ])["Subnets"]
            per_az = {}
            for subnet in sorted(subnets, key=lambda s: s["SubnetId"]):
                per_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
            subnet_ids = [per_az[az] for az in sorted(per_az)][:num_subnets]
            if len(subnet_ids) >= min(num_subnets, 2):
                _net_cache["net"] = (vpc_id, subnet_ids)
                return _net_cache["net"]
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
        try:
            ec2.create_tags(Resources=[vpc_id], Tags=_tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}])
        except Exception:
            pass
        azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        subnet_ids = []
        for i in range(num_subnets):
            az = azs[i % len(azs)]["ZoneName"]
            sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
            subnet_ids.append(sid)
            ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        _net_cache["net"] = (vpc_id, subnet_ids)
        return _net_cache["net"]

    def _create_load_balancer(name=None, subnet_ids=None, **kwargs):
        name = _clamp_name(name or ctx.unique_name("sim2real-behav-lb-"))
        if subnet_ids is None:
            _, subnet_ids = _setup_network()
        params = dict(
            Name=name,
            Subnets=subnet_ids,
            Type=kwargs.pop("Type", "application"),
            Scheme=kwargs.pop("Scheme", "internal"),
            Tags=kwargs.pop("Tags", _tags_kv()),
        )
        params.update(kwargs)
        lb = _retry_throttled(lambda: elb.create_load_balancer(**params))["LoadBalancers"][0]
        arn = lb["LoadBalancerArn"]
        ctx.on_cleanup(lambda: elb.delete_load_balancer(LoadBalancerArn=arn))
        return lb

    lb = _create_load_balancer()
    arn = lb["LoadBalancerArn"]

    elb.delete_load_balancer(LoadBalancerArn=arn)

    def probe():
        # None while the deleted load balancer still resolves; (code, message) once refused.
        try:
            return _error(lambda: elb.describe_load_balancers(LoadBalancerArns=[arn]))
        except AssertionError:
            return None

    code, message = _poll_until(
        probe,
        lambda c: c is not None,
        timeout_s=60,
        interval_s=3,
        description="deleted load balancer no longer resolving",
    )
    assert code == "LoadBalancerNotFound", f"expected not-found error, got {code}"
    assert message == "One or more load balancers not found", f"MSG={message!r}"


# Teardown waits (bounded) for AWS-managed ENIs to leave: a load balancer, endpoint, cluster or
# instance in this VPC deletes asynchronously and its ENIs linger, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Retry that inside one window shared
# by all of a check's network deletes, then raise naming the ENIs still attached.
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
        _time.sleep(10)
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
        _time.sleep(10)


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
