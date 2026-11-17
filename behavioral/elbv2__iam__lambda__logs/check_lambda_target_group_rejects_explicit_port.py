"""lambda-target-group-rejects-explicit-port."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-target-group-rejects-explicit-port"
GROUP = "overly-permissive"
SERVICES = ["elbv2", "iam", "lambda", "logs"]

_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_SID = "sim2real-elbv2-invoke"
_ELB_PRINCIPAL = "elasticloadbalancing.amazonaws.com"

#: AWS returns the same code and message for RegisterTargets, DeregisterTargets and
#: DescribeTargetHealth when a Lambda target names an explicit Port.
_PORT_NOT_ALLOWED = ("ValidationError", "Port cannot be specified for Lambda function targets")


def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=3.0, description="condition"):
    """Bounded retry. RAISES on timeout -- never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _expect_error(fn, code, message):
    """Calls fn(); raises if it unexpectedly succeeds; asserts the exact code and message."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert (err["Code"], err["Message"]) == (code, message), (
            f"got error {(err['Code'], err['Message'])!r}, expected {(code, message)!r}")
        return
    raise AssertionError(f"expected ({code}, {message!r}) but the call succeeded: {result!r}")


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST)["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return name, arn


def _reap_log_group(ctx, fn_name):
    """Registered BEFORE create_function so LIFO runs it AFTER the function delete: a buffered
    flush can recreate /aws/lambda/<fn> after one delete."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"

    def _reap():
        for _ in range(4):
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
            time.sleep(10)
            found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups") or []
            if not any(g["logGroupName"] == group for g in found):
                return
        raise RuntimeError(f"log group {group} reappeared after 4 delete rounds")

    ctx.on_cleanup(_reap)


def _create_lambda(ctx, role_arn):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    _reap_log_group(ctx, name)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "lambda_function.py",
            "def lambda_handler(event, context):\n    return {'statusCode': 200}\n",
        )

    def _try_create():
        try:
            return lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.lambda_handler", Code={"ZipFile": buf.getvalue()},
                Timeout=10, MemorySize=128,
            )["FunctionArn"]
        except ClientError as exc:
            # IAM propagation of the freshly created execution role only.
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                return None
            raise

    arn = _poll_until(_try_create, lambda a: a is not None, timeout_s=120, interval_s=5,
                      description=f"lambda {name} accepting the freshly created execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    _poll_until(lambda: lam.get_function_configuration(FunctionName=name).get("State"),
                lambda s: s == "Active", timeout_s=120, interval_s=3,
                description=f"lambda {name} reaching State=Active")
    return name, arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterTargets, DeregisterTargets and DescribeTargetHealth each refuse a Lambda target
    that names an explicit Port with ValidationError, storing nothing; the same calls with no
    Port succeed."""
    elb = ctx.client("elbv2")
    lam = ctx.client("lambda")

    _, role_arn = _create_lambda_role(ctx)
    fn_name, fn_arn = _create_lambda(ctx, role_arn)

    tg = elb.create_target_group(
        Name=_clamp_name(ctx.unique_name("sim2real-behav-tg-")), TargetType="lambda")["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(_teardown(lambda: elb.delete_target_group(TargetGroupArn=tg_arn),
                             "TargetGroupNotFound"))

    lam.add_permission(FunctionName=fn_name, StatementId=_SID, Action="lambda:InvokeFunction",
                       Principal=_ELB_PRINCIPAL, SourceArn=tg_arn)
    ctx.on_cleanup(_teardown(
        lambda: lam.remove_permission(FunctionName=fn_name, StatementId=_SID),
        "ResourceNotFoundException"))

    def _health():
        return elb.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]

    # ---- RegisterTargets refuses an explicit Port, at both ends of the valid range, and stores
    # ---- nothing. --------------------------------------------------------------------------
    for port in (1, 65535):
        _expect_error(
            lambda p=port: elb.register_targets(
                TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn, "Port": p}]),
            *_PORT_NOT_ALLOWED)
    assert _health() == [], f"a refused RegisterTargets with Port left {_health()!r} registered"

    # ---- positive control: RegisterTargets with no Port succeeds. ----------------------------
    elb.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn}])
    ctx.on_cleanup(_teardown(
        lambda: elb.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn}]),
        "TargetGroupNotFound"))
    registered = _health()
    assert [t["Target"] for t in registered] == [{"Id": fn_arn, "AvailabilityZone": "all"}], (
        f"after registering with no Port, DescribeTargetHealth listed targets {registered!r}, "
        f"expected a single entry for {fn_arn!r}")
    assert registered[0]["TargetHealth"] == {
        "State": "unused", "Reason": "Target.NotInUse",
        "Description": "Target group is not configured to receive traffic from the load balancer",
    }, f"the registered target's health was {registered[0]['TargetHealth']!r}"

    # ---- DescribeTargetHealth refuses an explicit Port on a registered target, and the
    # ---- registration is unaffected. ----------------------------------------------------------
    for port in (1, 65535):
        _expect_error(
            lambda p=port: elb.describe_target_health(
                TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn, "Port": p}]),
            *_PORT_NOT_ALLOWED)
    assert _health() == registered, (
        f"a refused DescribeTargetHealth with Port changed the registration to {_health()!r}, "
        f"expected it unchanged from {registered!r}")

    # ---- positive control: DescribeTargetHealth with no Port succeeds and matches the
    # ---- unfiltered listing. -------------------------------------------------------------------
    filtered = elb.describe_target_health(
        TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn}])["TargetHealthDescriptions"]
    assert filtered == registered, (
        f"DescribeTargetHealth filtered on {fn_arn!r} with no Port returned {filtered!r}, "
        f"expected {registered!r}")

    # ---- DeregisterTargets refuses an explicit Port, and the target stays registered. --------
    for port in (1, 65535):
        _expect_error(
            lambda p=port: elb.deregister_targets(
                TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn, "Port": p}]),
            *_PORT_NOT_ALLOWED)
    assert _health() == registered, (
        f"a refused DeregisterTargets with Port changed the registration to {_health()!r}, "
        f"expected it unchanged from {registered!r}")

    # ---- positive control: DeregisterTargets with no Port succeeds. --------------------------
    elb.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn}])
    assert _health() == [], f"after deregistering with no Port, DescribeTargetHealth listed {_health()!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
