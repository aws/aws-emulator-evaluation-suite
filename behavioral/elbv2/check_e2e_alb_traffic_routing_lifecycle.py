"""e2e-alb-traffic-routing-lifecycle."""
from __future__ import annotations

import io
import time
import zipfile
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-alb-traffic-routing-lifecycle"
GROUP = "e2e"
SERVICES = ["elbv2"]
#: The default service-class budget; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Lambda target registered behind an ALB reports unavailable/Target.HealthCheckDisabled and
    leaves target health on deregistration; each deleted rule, listener, target group and load
    balancer then refuses reads and updates with its exact not-found error."""
    elbv2 = ctx.client("elbv2")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    ec2 = ctx.client("ec2")

    subnet_a, subnet_b = _alb_subnets(ctx, ec2)

    # A Lambda target needs no live HTTP backend.
    role_name = _short_name(ctx, "sim2real-alb-role-", 64)
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    import json

    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role(RoleName=role_name)))

    func_name = _short_name(ctx, "sim2real-alb-fn-", 64)
    code_zip = _make_lambda_zip()
    function_arn = _create_function_with_retry(lam, func_name, role_arn, code_zip)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: lam.delete_function(FunctionName=func_name)))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=func_name)["State"],
        lambda state: state == "Active",
        interval_s=3.0,
    )

    lb_name = _short_name(ctx, "sim2real-alb-", 32)
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name, Subnets=[subnet_a, subnet_b], Type="application", Scheme="internal", Tags=_tags_kv()
    )["LoadBalancers"][0]["LoadBalancerArn"]
    lb_prefix = f"arn:aws:elasticloadbalancing:{ctx.region}:{ctx.account}:loadbalancer/app/{lb_name}/"
    assert lb_arn.startswith(lb_prefix), f"expected the LB ARN to start {lb_prefix!r}, got {lb_arn!r}"
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        interval_s=10.0,
    )

    tg_name = _short_name(ctx, "sim2real-alb-tg-", 32)
    tg_arn = elbv2.create_target_group(Name=tg_name, TargetType="lambda", Tags=_tags_kv())["TargetGroups"][0]["TargetGroupArn"]
    tg_prefix = f"arn:aws:elasticloadbalancing:{ctx.region}:{ctx.account}:targetgroup/{tg_name}/"
    assert tg_arn.startswith(tg_prefix), f"expected the TG ARN to start {tg_prefix!r}, got {tg_arn!r}"
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn)))

    # ELB validates invoke permission synchronously in RegisterTargets, so grant it first.
    lam.add_permission(
        FunctionName=func_name,
        StatementId="sim2real-elb-invoke",
        Action="lambda:InvokeFunction",
        Principal="elasticloadbalancing.amazonaws.com",
        SourceArn=tg_arn,
    )
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": function_arn}])

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        Tags=_tags_kv(),
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))

    rule_arn = elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=10,
        Conditions=[{"Field": "path-pattern", "Values": ["/api/*"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        Tags=_tags_kv(),
    )["Rules"][0]["RuleArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_rule(RuleArn=rule_arn)))

    # Lambda target groups have health checks off by default, so an accepted target reports
    # "unavailable"/"Target.HealthCheckDisabled" rather than "healthy".
    def _probe_health():
        descs = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
        return {d["Target"]["Id"]: d["TargetHealth"] for d in descs}

    health = _poll_until(
        _probe_health,
        lambda h: h.get(function_arn, {}).get("State") == "unavailable",
        interval_s=3.0,
    )
    assert health[function_arn]["State"] == "unavailable", (
        f"expected the newly-registered lambda target's state to be 'unavailable' "
        f"(lambda target groups have health checks disabled by default), got {health[function_arn]['State']!r}"
    )
    assert health[function_arn]["Reason"] == "Target.HealthCheckDisabled", (
        f"expected reason 'Target.HealthCheckDisabled' confirming the target was accepted into the "
        f"routing set rather than left pending, got {health[function_arn].get('Reason')!r}"
    )

    elbv2.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": function_arn}])
    _poll_until(
        lambda: elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"],
        lambda descs: function_arn not in {d["Target"]["Id"] for d in descs},
        interval_s=3.0,
    )

    # Delete in dependency order and confirm each resource is unreadable afterwards.
    elbv2.delete_rule(RuleArn=rule_arn)
    refused = _expect_error(lambda: elbv2.describe_rules(RuleArns=[rule_arn]), ("RuleNotFound",))
    expected_message = "One or more rules not found"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'
    rules = [r["RuleArn"] for r in elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]]
    assert rule_arn not in rules, f"deleted rule {rule_arn} still listed on its listener"
    refused = _expect_error(lambda: elbv2.modify_rule(RuleArn=rule_arn, Conditions=[{"Field": "path-pattern", "Values": ["/x/*"]}]),
                            ("RuleNotFound",))
    expected_message = f"Rule '{rule_arn}' not found"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'

    elbv2.delete_listener(ListenerArn=listener_arn)
    refused = _expect_error(lambda: elbv2.describe_listeners(ListenerArns=[listener_arn]), ("ListenerNotFound",))
    expected_message = "One or more listeners not found"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'
    listeners = [
        li["ListenerArn"]
        for page in elbv2.get_paginator("describe_listeners").paginate(LoadBalancerArn=lb_arn)
        for li in page.get("Listeners", [])
    ]
    assert listener_arn not in listeners, f"deleted listener {listener_arn} still listed on its LB"
    refused = _expect_error(lambda: elbv2.modify_listener(ListenerArn=listener_arn, Port=81), ("ListenerNotFound",))
    expected_message = f"Listener '{listener_arn}' not found"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'

    elbv2.delete_target_group(TargetGroupArn=tg_arn)
    refused = _expect_error(lambda: elbv2.describe_target_groups(TargetGroupArns=[tg_arn]), ("TargetGroupNotFound",))
    expected_message = "One or more target groups not found"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'
    refused = _expect_error(lambda: elbv2.describe_target_groups(Names=[tg_name]), ("TargetGroupNotFound",))
    expected_message = "One or more target groups not found"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'
    refused = _expect_error(lambda: elbv2.modify_target_group(TargetGroupArn=tg_arn, HealthCheckEnabled=True),
                            ("TargetGroupNotFound",))
    expected_message = f"Target groups '{tg_arn}' not found"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'

    elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except ClientError as exc:
            _assert_error(exc, ("LoadBalancerNotFound",))
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"load balancer {lb_arn} still readable after delete_load_balancer")
        time.sleep(3.0)
    refused = _expect_error(lambda: elbv2.describe_load_balancers(Names=[lb_name]), ("LoadBalancerNotFound",))
    expected_message = f"Load balancers '[{lb_name}]' not found"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'
    refused = _expect_error(lambda: elbv2.add_tags(ResourceArns=[lb_arn], Tags=[{"Key": "after", "Value": "delete"}]),
                            ("LoadBalancerNotFound",))
    expected_message = "One or more load balancers not found"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'




def _assert_error(exc, codes, *, status=400, contains=()) -> None:
    """Grade a ClientError on code, HTTP status, the exact message and the ids it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert got_status == status, f"expected HTTP {status} with {code}, got {got_status!r}"
    assert msg.strip(), f"expected the exact message with {code}"
    for want in contains:
        assert want in msg, f"expected the {code} message to name {want!r}, got {msg!r}"


def _expect_error(fn, codes, *, status=400, contains=()):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status, contains=contains)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


def _ignore_not_found(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if "NotFound" not in exc.response.get("Error", {}).get("Code", ""):
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = POLL_BUDGET_S, interval_s: float) -> Any:
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


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-alb"}]


def _alb_subnets(ctx, ec2) -> tuple[str, str]:
    """Reuse the shared network's subnets across >=2 AZs, else provision a VPC with 2 subnets."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            ids = list(by_az.values())
            return ids[0], ids[1]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.92.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_kv()}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    ][:2]
    if len(azs) < 2:
        raise AssertionError(f"region {ctx.region} does not expose >=2 available AZs to attach an ALB to")
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.92.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _ignore_not_found(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
    return subnet_ids[0], subnet_ids[1]


def _make_lambda_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "lambda_function.py",
            "def handler(event, context):\n    return {'statusCode': 200, 'body': 'ok'}\n",
        )
    return buf.getvalue()


def _create_function_with_retry(lam, func_name: str, role_arn: str, code_zip: bytes) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code_zip},
                Timeout=10,
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-alb"},
            )
            return resp["FunctionArn"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "InvalidParameterValueException":
                last_exc = exc
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"lambda create_function never succeeded (IAM propagation?): {last_exc}")


# A load balancer, endpoint, cluster, function or instance deletes asynchronously: its ENIs stay
# in the subnet / security group, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc
# fails with DependencyViolation. Wait (bounded) for the ENIs to go and retry inside that window.
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
