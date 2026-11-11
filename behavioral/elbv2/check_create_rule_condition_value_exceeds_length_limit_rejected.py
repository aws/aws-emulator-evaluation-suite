"""create-rule-condition-value-exceeds-length-limit-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "create-rule-condition-value-exceeds-length-limit-rejected"
GROUP = "negative-classes"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A path-pattern condition value over the 128-character maximum is rejected with ValidationError
    and no rule is created; the same listener then accepts an in-limit value at the same priority."""
    elbv2 = ctx.client("elbv2")
    cleanup_deadline = [None]
    az_to_subnet = _ensure_azs_subnets(ctx, cleanup_deadline, min_azs=2)
    subnet_a, subnet_b = list(az_to_subnet.values())[:2]

    lb_name = _short_name(ctx, "sim2real-rulelen-", 32)
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name, Subnets=[subnet_a, subnet_b], Type="application", Scheme="internal", Tags=_tags_kv()
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=240.0,
        interval_s=10.0,
    )

    fixed_response = {"Type": "fixed-response", "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": "ok"}}
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80, DefaultActions=[fixed_response], Tags=_tags_kv()
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))

    priority = 1
    too_long_value = "/" + ("a" * 200)  # documented max length for a path-pattern value is 128 chars

    code, message = _error(
        lambda: elbv2.create_rule(
            ListenerArn=listener_arn,
            Priority=priority,
            Conditions=[{"Field": "path-pattern", "Values": [too_long_value]}],
            Actions=[fixed_response],
        )
    )
    assert code == "ValidationError", f"expected ValidationError for a 200-char path-pattern value, got {code!r}"
    expected = "Condition value for 'path-pattern' cannot contain more than 128 characters"
    assert message == expected, f"MSG={message!r}"
    rules_after_reject = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    assert all(r["Priority"] in ("default",) or int(r["Priority"]) != priority for r in rules_after_reject), (
        f"a rule at priority {priority} exists after the oversized value should have been rejected: {rules_after_reject}"
    )

    ok_value = "/ok"
    resp = elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=priority,
        Conditions=[{"Field": "path-pattern", "Values": [ok_value]}],
        Actions=[fixed_response],
        Tags=_tags_kv(),
    )
    rule_arn = resp["Rules"][0]["RuleArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_rule(RuleArn=rule_arn)))
    assert resp["Rules"][0]["Conditions"][0]["Values"] == [ok_value], (
        f"expected create_rule to echo back {[ok_value]!r}, got {resp['Rules'][0]['Conditions'][0]['Values']!r}"
    )
    rules_after_ok = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    assert any(r.get("RuleArn") == rule_arn for r in rules_after_ok), (
        f"expected rule {rule_arn} to be visible in describe_rules after creation, got {rules_after_ok}"
    )


# ===== helpers =====


def _tags_kv() -> list:
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    ]


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Run ``fn``, which the service refuses, and return the refusal's (code, message)."""
    # The elbv2 model places no length constraint on Conditions[].Values, so botocore
    # never validates this client-side (confirmed against the service model) -- every
    # call here reaches the service, and a ParamValidationError would mean the request
    # never left the SDK, which is not evidence the service rejected anything.
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _ignore_not_found(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if "NotFound" not in exc.response.get("Error", {}).get("Code", ""):
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _short_name(ctx: Any, prefix: str, max_len: int) -> str:
    name = ctx.unique_name(prefix)
    return name[:max_len].rstrip("-")


def _delete_with_retry(fn: Callable[[], Any], deadline_holder: list, per_wait: float = 3.0) -> None:
    """Retry ``fn`` while it fails with DependencyViolation, until the shared deadline passes.

    ALB deletion returns before its ENIs actually detach from their subnets, so an immediate
    DeleteSubnet/DeleteVpc issued right after DeleteLoadBalancer can race a lingering ENI. The
    deadline is shared across every call in this check's teardown (initialised on first use) so
    the combined retries still fit inside ``ctx.on_cleanup``'s own budget.
    """
    from botocore.exceptions import ClientError

    if deadline_holder[0] is None:
        deadline_holder[0] = time.monotonic() + 50.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "DependencyViolation" or time.monotonic() >= deadline_holder[0]:
                raise
            time.sleep(per_wait)


def _ensure_azs_subnets(ctx, cleanup_deadline: list, min_azs: int = 2) -> dict:
    """Create-or-adopt a subnet-per-AZ map spanning at least ``min_azs`` AZs.

    A freshly provisioned account may have no default VPC at all, so this never assumes one
    exists: it adopts the default VPC's subnets when there are enough of them, and otherwise
    provisions a small dedicated VPC with one subnet per AZ (no internet gateway or route table
    needed -- the load balancer this check creates is internal-scheme only).
    """
    ec2 = ctx.client("ec2")
    adopted = _adopt_default_vpc_azs(ec2, min_azs, ctx=ctx)
    if adopted is not None:
        return adopted
    return _create_dedicated_vpc_azs(ctx, ec2, cleanup_deadline, min_azs)


def _adopt_default_vpc_azs(ec2: Any, min_azs: int, *, ctx) -> dict | None:
    # The DescribeVpcs filter is "isDefault" (camelCase) -- there is no "is-default" filter.
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    by_az: dict[str, str] = {}
    for s in sorted(subnets, key=lambda s: s["SubnetId"]):
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < min_azs:
        return None
    azs = sorted(by_az)[:min_azs]
    return {az: by_az[az] for az in azs}


def _create_dedicated_vpc_azs(ctx: Any, ec2: Any, cleanup_deadline: list, min_azs: int) -> dict:
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    if len(azs) < min_azs:
        raise AssertionError(f"region exposes only {len(azs)} available AZs, need at least {min_azs}")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.66.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": _tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), cleanup_deadline))

    by_az: dict[str, str] = {}
    for i, az in enumerate(azs[:min_azs]):
        zone = az["ZoneName"]
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.66.{i}.0/24",
            AvailabilityZone=zone,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": _tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-subnet-")}],
                }
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda sid=subnet_id: _delete_with_retry(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid), cleanup_deadline)
        )
        by_az[zone] = subnet_id
    return by_az


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
