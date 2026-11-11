"""deregister-targets-transitions-state."""
from __future__ import annotations

import ipaddress
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-targets-transitions-state"
GROUP = 'target-registration'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeregisterTargets moves an in-service target of a listener-attached group into 'draining'."""

    _net_cache = {}
    elb = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    def _safe(fn):
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TargetGroupNotFound":
                raise

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

    def _create_target_group(name=None, vpc_id=None, **kwargs):
        name = _clamp_name(name or ctx.unique_name("sim2real-behav-tg-"))
        params = dict(Name=name, Protocol="HTTP", Port=80, TargetType="ip")
        params.update(kwargs)
        if params.get("TargetType") != "lambda":
            if vpc_id is None:
                vpc_id, _ = _setup_network()
            params.setdefault("VpcId", vpc_id)
        elif vpc_id is not None:
            params["VpcId"] = vpc_id
        params.setdefault("Tags", _tags_kv())
        tg = _retry_throttled(lambda: elb.create_target_group(**params))["TargetGroups"][0]
        arn = tg["TargetGroupArn"]
        ctx.on_cleanup(lambda: _delete_target_group_when_free(elb, arn))
        return tg

    def _create_load_balancer(subnet_ids, **kwargs):
        name = _clamp_name(ctx.unique_name("sim2real-behav-lb-"))
        params = dict(Name=name, Subnets=subnet_ids, Type="application", Scheme="internal", Tags=_tags_kv())
        params.update(kwargs)
        lb = _retry_throttled(lambda: elb.create_load_balancer(**params))["LoadBalancers"][0]
        arn = lb["LoadBalancerArn"]

        def _drop_lb():
            try:
                elb.delete_load_balancer(LoadBalancerArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            for _ in range(90):
                try:
                    elb.describe_load_balancers(LoadBalancerArns=[arn])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                        raise
                    return
                time.sleep(2)

        ctx.on_cleanup(_drop_lb)
        return lb

    def _wait_for_lb_active(lb_arn, timeout_s=300):
        lb = _poll_until(
            lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0],
            lambda x: x["State"]["Code"] in ("active", "active_impaired", "failed"),
            timeout_s=timeout_s,
            interval_s=5,
            description="load balancer reaching a terminal provisioning state",
        )
        assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"

    def _create_listener(lb_arn, tg_arn, **kwargs):
        params = dict(
            LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        )
        params.update(kwargs)
        listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][0]
        arn = listener["ListenerArn"]
        ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=arn))
        return listener

    def _ip_in_subnet(subnet_id, offset=100):
        # The target's AZ must be enabled for the load balancer (else Target.NotInUse), so the
        # IP comes from one of the LB's own subnets, not just anywhere in the VPC CIDR.
        cidr = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]["CidrBlock"]
        net = ipaddress.ip_network(cidr)
        return str(net.network_address + offset)

    vpc_id, subnet_ids = _setup_network()
    lb = _create_load_balancer(subnet_ids)
    _wait_for_lb_active(lb["LoadBalancerArn"])

    tg = _create_target_group(TargetType="ip", Port=80, Protocol="HTTP", vpc_id=vpc_id)
    _create_listener(lb["LoadBalancerArn"], tg["TargetGroupArn"])

    # The target group only starts health-checking once the load balancer's control
    # plane has actually picked up the listener -> target-group association; register
    # before that lands and the target can sit in 'unused' far longer than the health
    # check interval would suggest.
    _poll_until(
        lambda: elb.describe_target_groups(TargetGroupArns=[tg["TargetGroupArn"]])["TargetGroups"][0].get(
            "LoadBalancerArns", []
        ),
        lambda arns: lb["LoadBalancerArn"] in arns,
        timeout_s=60,
        interval_s=2,
        description="target group showing the attached load balancer",
    )

    target = {"Id": _ip_in_subnet(subnet_ids[0], 102), "Port": 80}
    _retry_throttled(lambda: elb.register_targets(TargetGroupArn=tg["TargetGroupArn"], Targets=[target]))
    ctx.on_cleanup(lambda: _safe(lambda: elb.deregister_targets(TargetGroupArn=tg["TargetGroupArn"], Targets=[target])))

    def probe():
        try:
            resp = elb.describe_target_health(
                TargetGroupArn=tg["TargetGroupArn"], Targets=[target]
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidTargetException":
                return None
            raise
        descs = resp["TargetHealthDescriptions"]
        if not descs:
            return None
        return descs[0]["TargetHealth"]["State"]

    # A target the load balancer does not health-check sits in 'unused' regardless of
    # DeregisterTargets, so wait for it to leave 'unused' first.
    in_service_state = _poll_until(
        probe,
        lambda s: s not in (None, "unused"),
        timeout_s=90,
        interval_s=3,
        description="registered target leaving 'unused' under the attached load balancer",
    )
    assert in_service_state in ("initial", "healthy", "unhealthy", "unavailable"), (
        f"expected the target to be in service before deregistering, got {in_service_state!r}"
    )

    elb.deregister_targets(TargetGroupArn=tg["TargetGroupArn"], Targets=[target])

    final_state = _poll_until(
        probe,
        lambda s: s == "draining",
        timeout_s=90,
        interval_s=2,
        description="target entering 'draining' immediately after deregister",
    )
    assert final_state == "draining", f"expected 'draining' right after deregister, got {final_state!r}"


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
