"""deletion-protection-blocks-delete."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deletion-protection-blocks-delete"
GROUP = 'overly-permissive'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OperationNotPermitted is raised when deleting a deletion-protected load balancer; after disabling protection the delete succeeds and the ARN 404s."""

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

    def _error_code(fn):
        delays = [3, 6, 12, 24, 30]
        code = message = None
        for attempt in range(5):
            try:
                fn()
                code = message = None
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                message = exc.response.get("Error", {}).get("Message")
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
        vpc_tags = _tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}]
        vpc_id = ec2.create_vpc(
            CidrBlock="10.0.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": vpc_tags}]
        )["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
        azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        subnet_ids = []
        for i in range(num_subnets):
            az = azs[i % len(azs)]["ZoneName"]
            sid = ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az,
                TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
            )["Subnet"]["SubnetId"]
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
        ctx.on_cleanup(lambda: _delete_load_balancer(elb, arn))
        return lb

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

    def _create_listener(load_balancer_arn, **kwargs):
        params = dict(LoadBalancerArn=load_balancer_arn, Protocol="HTTP", Port=80)
        params.update(kwargs)
        listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][0]
        arn = listener["ListenerArn"]
        ctx.on_cleanup(_teardown(lambda: elb.delete_listener(ListenerArn=arn), "ListenerNotFound"))
        return listener

    def _wait_for_lb_active(arn, timeout_s=230, interval_s=10):
        return _poll_until(
            lambda: elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0],
            lambda lb: lb["State"]["Code"] in ("active", "active_impaired", "failed"),
            timeout_s=timeout_s, interval_s=interval_s,
            description="load balancer reaching a terminal state",
        )

    lb = _create_load_balancer()
    lb_arn = lb["LoadBalancerArn"]
    _wait_for_lb_active(lb_arn)

    elb.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn,
        Attributes=[{"Key": "deletion_protection.enabled", "Value": "true"}],
    )

    code, message = _error_code(lambda: elb.delete_load_balancer(LoadBalancerArn=lb_arn))
    assert code == "OperationNotPermitted", f"expected OperationNotPermitted while deletion protection is enabled, got {code!r}"
    assert message == (
        f"Load balancer '{lb_arn}' cannot be deleted because deletion protection is enabled"
    ), message

    # The blocked delete must not have taken effect: an independent read still finds the load
    # balancer, still protected.
    survived = elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
    assert survived["LoadBalancerArn"] == lb_arn, f"expected {lb_arn} to still exist after the blocked delete, got {survived!r}"
    attrs_after_block = {
        a["Key"]: a["Value"]
        for a in elb.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)["Attributes"]
    }
    assert attrs_after_block.get("deletion_protection.enabled") == "true", (
        f"expected deletion_protection.enabled to remain 'true' after the blocked delete, got {attrs_after_block.get('deletion_protection.enabled')!r}"
    )

    elb.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn,
        Attributes=[{"Key": "deletion_protection.enabled", "Value": "false"}],
    )
    elb.delete_load_balancer(LoadBalancerArn=lb_arn)

    code2, message2 = _poll_until(
        lambda: _error_code(lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])),
        lambda c: c[0] is not None,
        timeout_s=90, interval_s=3, description="protected load balancer deleted after unprotect",
    )
    assert code2 == "LoadBalancerNotFound", f"expected LoadBalancerNotFound after disabling protection and deleting, got {code2!r}"
    assert message2 == "One or more load balancers not found", message2


# ===== helpers =====

# EC2 network teardown outlasts the resources placed in the VPC. A load balancer, endpoint or
# instance deletes ASYNCHRONOUSLY: its delete returns while its ENIs still sit in the subnet, so
# DeleteSubnet / DeleteVpc answers DependencyViolation until they drain. _delete_net retries that one
# code inside a bounded window shared by all of one check's network deletes, treats the resource's
# own not-found code as already gone, and RAISES on anything else or on timeout, naming the ENIs
# still attached, so the runner records the leak. The window fits the cleanup budget.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_NOT_FOUND = {
    "delete_vpc": "InvalidVpcID.NotFound",
    "delete_subnet": "InvalidSubnetID.NotFound",
    "delete_security_group": "InvalidGroup.NotFound",
}
_NET_DEADLINES: dict = {}


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own ``not_found`` codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _delete_net(client, op, **ident):
    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while True:
        try:
            getattr(client, op)(**ident)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == _NET_NOT_FOUND[op]:
                return
            if code != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}) still answered DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        time.sleep(10)


def _net_enis(client, flt):
    if not flt:
        return []
    enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


def _delete_load_balancer(elbv2, arn):
    """Unprotect, then delete, a load balancer this check created; already gone is fine."""
    _teardown(
        lambda: elbv2.modify_load_balancer_attributes(
            LoadBalancerArn=arn,
            Attributes=[{"Key": "deletion_protection.enabled", "Value": "false"}],
        ),
        "LoadBalancerNotFound",
    )()
    _teardown(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn), "LoadBalancerNotFound")()


def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
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
