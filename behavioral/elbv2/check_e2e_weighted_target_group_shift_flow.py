"""e2e-weighted-target-group-shift-flow."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "e2e-weighted-target-group-shift-flow"
GROUP = "e2e"
SERVICES = ["elbv2"]

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two target groups behind a single weighted forward rule: register a target in
    each, confirm DescribeRules reflects the initial weight split, shift the weights
    via ModifyRule, and confirm DescribeRules reflects the new split before teardown."""
    elbv2 = ctx.client("elbv2")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    subnet_a, subnet_b = _default_vpc_two_az_subnets(ctx)

    role_name = _short_name(ctx, "sim2real-wtg-role-", 64)
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=list(_TAGS)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role(RoleName=role_name)))

    func_name = _short_name(ctx, "sim2real-wtg-fn-", 64)
    function_arn = _create_function_with_retry(lam, func_name, role_arn, _make_lambda_zip(), _TAGS)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: lam.delete_function(FunctionName=func_name)))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=func_name)["State"],
        lambda state: state == "Active",
        timeout_s=90.0,
        interval_s=3.0,
    )

    tg1_name = _short_name(ctx, "sim2real-wtg-a-", 32)
    tg2_name = _short_name(ctx, "sim2real-wtg-b-", 32)
    tg1_arn = elbv2.create_target_group(
        Name=tg1_name, TargetType="lambda", Tags=list(_TAGS)
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: _delete_target_group_when_free(elbv2, tg1_arn)))
    tg2_arn = elbv2.create_target_group(
        Name=tg2_name, TargetType="lambda", Tags=list(_TAGS)
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: _delete_target_group_when_free(elbv2, tg2_arn)))

    for i, tg_arn in enumerate((tg1_arn, tg2_arn)):
        # NOTE: elasticloadbalancing must be granted invoke permission on the
        # function BEFORE RegisterTargets, since ELB validates invoke permission
        # when a lambda target is registered against a target group. That
        # validation reads the function's resource policy, and a just-added
        # statement can take a few seconds to propagate, so RegisterTargets is
        # retried on AccessDenied rather than assumed synchronous.
        lam.add_permission(
            FunctionName=func_name,
            StatementId=f"sim2real-elb-invoke-{i}",
            Action="lambda:InvokeFunction",
            Principal="elasticloadbalancing.amazonaws.com",
            SourceArn=tg_arn,
        )
        _register_target_with_retry(elbv2, tg_arn, function_arn)

    lb_name = _short_name(ctx, "sim2real-wtg-lb-", 32)
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name, Subnets=[subnet_a, subnet_b], Type="application", Scheme="internal", Tags=list(_TAGS)
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=240.0,
        interval_s=10.0,
    )

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg1_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))

    rule_arn = elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=5,
        Conditions=[{"Field": "path-pattern", "Values": ["/split/*"]}],
        Actions=[
            {
                "Type": "forward",
                "ForwardConfig": {
                    "TargetGroups": [
                        {"TargetGroupArn": tg1_arn, "Weight": 80},
                        {"TargetGroupArn": tg2_arn, "Weight": 20},
                    ]
                },
            }
        ],
    )["Rules"][0]["RuleArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_rule(RuleArn=rule_arn)))

    # --- both targets are registered and reflect a definitive routing-eligible state
    # (Lambda target groups have health checks disabled by default, so the reported
    # state is "unavailable"/"Target.HealthCheckDisabled" rather than "healthy") ---
    for tg_arn in (tg1_arn, tg2_arn):
        _poll_until(
            lambda tg_arn=tg_arn: {
                d["Target"]["Id"]: d["TargetHealth"]
                for d in elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
            }.get(function_arn, {}),
            lambda health: health.get("State") == "unavailable" and health.get("Reason") == "Target.HealthCheckDisabled",
            timeout_s=60.0,
            interval_s=3.0,
        )

    # --- initial weighted distribution ---
    weights = _rule_weights(elbv2, rule_arn)
    assert weights == {tg1_arn: 80, tg2_arn: 20}, (
        f"expected initial 80/20 split {tg1_arn}:80 {tg2_arn}:20, DescribeRules reported {weights!r}"
    )

    # --- shift the weights ---
    elbv2.modify_rule(
        RuleArn=rule_arn,
        Actions=[
            {
                "Type": "forward",
                "ForwardConfig": {
                    "TargetGroups": [
                        {"TargetGroupArn": tg1_arn, "Weight": 20},
                        {"TargetGroupArn": tg2_arn, "Weight": 80},
                    ]
                },
            }
        ],
    )
    shifted_weights = _rule_weights(elbv2, rule_arn)
    assert shifted_weights == {tg1_arn: 20, tg2_arn: 80}, (
        f"expected shifted 20/80 split {tg1_arn}:20 {tg2_arn}:80 after ModifyRule, "
        f"DescribeRules reported {shifted_weights!r}"
    )

    # --- teardown: rule, listener (frees the target groups), then both target groups ---
    elbv2.delete_rule(RuleArn=rule_arn)
    rule_code, rule_message = _client_error(lambda: elbv2.describe_rules(RuleArns=[rule_arn]))
    assert rule_code == "RuleNotFound", f"expected RuleNotFound for deleted rule {rule_arn}, got {rule_code!r}"
    expected = "One or more rules not found"
    assert rule_message == expected, f"expected message {expected!r}, got {rule_message!r}"

    elbv2.delete_listener(ListenerArn=listener_arn)
    listener_code, listener_message = _client_error(lambda: elbv2.describe_listeners(ListenerArns=[listener_arn]))
    assert listener_code == "ListenerNotFound", (
        f"expected ListenerNotFound for deleted listener {listener_arn}, got {listener_code!r}"
    )
    expected = "One or more listeners not found"
    assert listener_message == expected, f"expected message {expected!r}, got {listener_message!r}"

    elbv2.delete_target_group(TargetGroupArn=tg1_arn)
    elbv2.delete_target_group(TargetGroupArn=tg2_arn)
    for tg_arn in (tg1_arn, tg2_arn):
        tg_code, tg_message = _client_error(lambda tg_arn=tg_arn: elbv2.describe_target_groups(TargetGroupArns=[tg_arn]))
        assert tg_code == "TargetGroupNotFound", (
            f"expected TargetGroupNotFound for deleted target group {tg_arn}, got {tg_code!r}"
        )
        expected = "One or more target groups not found"
        assert tg_message == expected, f"expected message {expected!r}, got {tg_message!r}"


def _rule_weights(elbv2, rule_arn: str) -> dict[str, int]:
    rule = elbv2.describe_rules(RuleArns=[rule_arn])["Rules"][0]
    tgs = rule["Actions"][0]["ForwardConfig"]["TargetGroups"]
    return {t["TargetGroupArn"]: t["Weight"] for t in tgs}


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """(Code, Message) of the ClientError fn raises; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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


def _default_vpc_two_az_subnets(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to attach an ALB to")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not have subnets in >=2 Availability Zones for an ALB")
    ids = list(by_az.values())
    return ids[0], ids[1]


def _make_lambda_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "lambda_function.py",
            "def handler(event, context):\n    return {'statusCode': 200, 'body': 'ok'}\n",
        )
    return buf.getvalue()


def _register_target_with_retry(elbv2, tg_arn: str, function_arn: str) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 30.0
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": function_arn}])
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") == "AccessDenied":
                last_exc = exc
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(
        f"RegisterTargets on {tg_arn} never succeeded (lambda invoke permission propagation?): {last_exc}"
    )


def _create_function_with_retry(
    lam, func_name: str, role_arn: str, code_zip: bytes, tags: list[dict[str, str]]
) -> str:
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
                Tags={t["Key"]: t["Value"] for t in tags},
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
