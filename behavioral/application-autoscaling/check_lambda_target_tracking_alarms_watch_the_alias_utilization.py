"""lambda-target-tracking-alarms-watch-the-alias-utilization."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-target-tracking-alarms-watch-the-alias-utilization"
GROUP = "scaling-policies"
SERVICES = ["application-autoscaling"]

_NS = "lambda"
_DIM = "lambda:function:ProvisionedConcurrency"
_ALIAS = "live"
_TARGET = 0.7
_POLICY = "pc-utilization"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Target tracking on a Lambda alias mints only AlarmHigh (at the target) and AlarmLow (at 90%)
    on ProvisionedConcurrencyUtilization by FunctionName and Resource, both acting on the policy;
    deleting the policy removes both alarms.
    """
    aas = ctx.client("application-autoscaling")
    cw = ctx.client("cloudwatch")
    function, _version = _function_with_alias(ctx, _ALIAS)
    resource_id = f"function:{function}:{_ALIAS}"
    # Runs after the deregistration below (LIFO), removing any alarm the cascade left.
    ctx.on_cleanup(lambda: _delete_alarms(cw, f"TargetTracking-{resource_id}-"))

    # MinCapacity 0 avoids allocating any provisioned concurrency.
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=0, MaxCapacity=2)
    ctx.on_cleanup(lambda: _ignore_missing(
        lambda: aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                               ScalableDimension=_DIM),
        "ObjectNotFoundException"))

    put = aas.put_scaling_policy(
        PolicyName=_POLICY, ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration={
            "TargetValue": _TARGET,
            "PredefinedMetricSpecification": {
                "PredefinedMetricType": "LambdaProvisionedConcurrencyUtilization"},
        })
    names = [a["AlarmName"] for a in put["Alarms"]]
    assert len(names) == 2, f"a Lambda target-tracking policy listed {len(names)} alarms, expected 2"
    high = [n for n in names if n.startswith(f"TargetTracking-{resource_id}-AlarmHigh-")]
    low = [n for n in names if n.startswith(f"TargetTracking-{resource_id}-AlarmLow-")]
    assert len(high) == 1 and len(low) == 1, (
        f"alarm name shapes: {[n.replace(function, '<fn>') for n in names]!r}; expected one "
        f"TargetTracking-<resource id>-AlarmHigh-* and one -AlarmLow-*"
    )

    live = _poll_until(lambda: _alarms(cw, names), lambda found: set(found) == set(names),
                       timeout_s=60, description="both policy alarms being visible in CloudWatch")
    expected_dims = {"FunctionName": function, "Resource": f"{function}:{_ALIAS}"}
    for name in names:
        alarm = live[name]
        assert (alarm["Namespace"], alarm["MetricName"], alarm["Statistic"]) == (
                "AWS/Lambda", "ProvisionedConcurrencyUtilization", "Average"), (
            f"alarm watches {alarm['Namespace']}/{alarm['MetricName']} ({alarm['Statistic']})"
        )
        dims = {d["Name"]: d["Value"] for d in alarm["Dimensions"]}
        assert dims == expected_dims, (
            f"alarm dimensions were {sorted(dims)!r} with Resource "
            f"{dims.get('Resource', '').replace(function, '<fn>')!r}; expected FunctionName and "
            f"Resource=<fn>:{_ALIAS}"
        )
        assert len(alarm["AlarmActions"]) == 1 and alarm["AlarmActions"][0].startswith(
            put["PolicyARN"] + ":createdBy/"), (
            "the alarm's single action must be the policy that minted it"
        )
    h, lo = live[high[0]], live[low[0]]
    assert (h["ComparisonOperator"], h["Threshold"]) == ("GreaterThanThreshold", _TARGET), (
        f"AlarmHigh is {h['ComparisonOperator']} {h['Threshold']!r}, expected "
        f"GreaterThanThreshold {_TARGET!r}"
    )
    assert lo["ComparisonOperator"] == "LessThanThreshold" and abs(
            lo["Threshold"] - _TARGET * 0.9) < 1e-9, (
        f"AlarmLow is {lo['ComparisonOperator']} {lo['Threshold']!r}, expected "
        f"LessThanThreshold {_TARGET * 0.9:.2f}"
    )
    assert (h["EvaluationPeriods"], lo["EvaluationPeriods"]) == (3, 15), (
        f"evaluation periods high/low were {h['EvaluationPeriods']}/{lo['EvaluationPeriods']}"
    )

    described = aas.describe_scaling_policies(ServiceNamespace=_NS, ResourceId=resource_id,
                                              ScalableDimension=_DIM)["ScalingPolicies"]
    assert [sorted(a["AlarmName"] for a in p["Alarms"]) for p in described] == [sorted(names)], (
        "DescribeScalingPolicies does not list exactly the alarms PutScalingPolicy returned"
    )

    aas.delete_scaling_policy(PolicyName=_POLICY, ServiceNamespace=_NS, ResourceId=resource_id,
                              ScalableDimension=_DIM)
    remaining = _poll_until(lambda: _alarms(cw, names), lambda found: not found, timeout_s=90,
                            description="the policy's alarms being removed with the policy")
    assert not remaining, f"{len(remaining)} alarms survived DeleteScalingPolicy"


def _alarms(cw, names):
    out = {}
    for page in cw.get_paginator("describe_alarms").paginate(AlarmNames=names):
        for alarm in page["MetricAlarms"]:
            out[alarm["AlarmName"]] = alarm
    return out


def _delete_alarms(cw, prefix):
    left = []
    for page in cw.get_paginator("describe_alarms").paginate(AlarmNamePrefix=prefix):
        left.extend(a["AlarmName"] for a in page["MetricAlarms"])
    if left:
        cw.delete_alarms(AlarmNames=left)


_ROLE_PROPAGATION_S = 90.0
_SOURCE = "def handler(event, context):\n    return {'ok': True}\n"


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _zip_source():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("index.py", _SOURCE)
    return buf.getvalue()


def _ignore_missing(fn, *codes):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in codes:
            raise


def _function_with_alias(ctx, alias):
    """A published version of a fresh function behind ``alias``; returns (name, version).

    The function is never invoked, so Lambda creates no log group for it.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = ctx.unique_name("sim2real-aas-lam-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_role(RoleName=role_name),
                                           "NoSuchEntity"))
    name = ctx.unique_name("sim2real-behav-aas-fn-")
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        try:
            lam.create_function(FunctionName=name, Runtime="python3.12", Role=role_arn,
                                Handler="index.handler", Code={"ZipFile": _zip_source()},
                                Timeout=10, Tags={"sim2real": CHECK})
            break
        except ClientError as exc:
            # IAM propagation: Lambda refuses a role it cannot assume yet.
            if (exc.response["Error"]["Code"] != "InvalidParameterValueException"
                    or time.monotonic() > deadline):
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: _ignore_missing(lambda: lam.delete_function(FunctionName=name),
                                           "ResourceNotFoundException"))
    _poll_until(lambda: lam.get_function_configuration(FunctionName=name)["State"],
                lambda state: state == "Active", timeout_s=90,
                description=f"function {name!r} reaching State Active")
    version = lam.publish_version(FunctionName=name)["Version"]
    lam.create_alias(FunctionName=name, Name=alias, FunctionVersion=version)
    return name, version


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
