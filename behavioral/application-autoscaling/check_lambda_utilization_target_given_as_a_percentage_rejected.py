"""lambda-utilization-target-given-as-a-percentage-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-utilization-target-given-as-a-percentage-rejected"
GROUP = "scaling-policies"
SERVICES = ["application-autoscaling"]

_NS = "lambda"
_DIM = "lambda:function:ProvisionedConcurrency"
_ALIAS = "live"
_POLICY = "pc-utilization"
# The valid TargetValue range is per predefined metric; 70 is a valid DynamoDB utilization.
_PERCENT = 70.0
_FRACTION = 0.7


def _tt(value):
    return {"TargetValue": value,
            "PredefinedMetricSpecification": {
                "PredefinedMetricType": "LambdaProvisionedConcurrencyUtilization"}}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """LambdaProvisionedConcurrencyUtilization is a fraction: TargetValue 70 is refused with a
    ValidationException naming the 0.1-0.9 range and creates no policy or alarm; 0.7 is accepted.
    """
    aas = ctx.client("application-autoscaling")
    cw = ctx.client("cloudwatch")
    function, _version = _function_with_alias(ctx, _ALIAS)
    resource_id = f"function:{function}:{_ALIAS}"
    alarm_prefix = f"TargetTracking-{resource_id}-"
    # Runs after the deregistration below (LIFO), removing any alarm the cascade left.
    ctx.on_cleanup(lambda: _delete_alarms(cw, alarm_prefix))
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=0, MaxCapacity=2)
    ctx.on_cleanup(lambda: _ignore_missing(
        lambda: aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                               ScalableDimension=_DIM),
        "ObjectNotFoundException"))

    code, message = _error(lambda: aas.put_scaling_policy(
        PolicyName=_POLICY, ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyType="TargetTrackingScaling", TargetTrackingScalingPolicyConfiguration=_tt(_PERCENT)))
    assert code == "ValidationException", f"a percentage target was refused with {code!r}"
    expected = ("For predefined metric type LambdaProvisionedConcurrencyUtilization, target "
                f"value must be between '0.1' and '0.9', but was '{_PERCENT}'.")
    assert message == expected, f"refusal message {message!r}, expected {expected!r}"

    policies = aas.describe_scaling_policies(ServiceNamespace=_NS, ResourceId=resource_id,
                                             ScalableDimension=_DIM)["ScalingPolicies"]
    assert policies == [], (
        f"the refused policy is stored anyway: {[p['PolicyName'] for p in policies]!r}"
    )
    assert _alarm_names(cw, alarm_prefix) == [], "the refused policy minted CloudWatch alarms"

    # Positive control: the same policy expressed as a fraction is accepted.
    put = aas.put_scaling_policy(
        PolicyName=_POLICY, ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyType="TargetTrackingScaling", TargetTrackingScalingPolicyConfiguration=_tt(_FRACTION))
    assert len(put["Alarms"]) == 2, f"the accepted policy listed {len(put['Alarms'])} alarms"
    stored = aas.describe_scaling_policies(ServiceNamespace=_NS, ResourceId=resource_id,
                                           ScalableDimension=_DIM)["ScalingPolicies"]
    assert [(p["PolicyName"], p["TargetTrackingScalingPolicyConfiguration"]["TargetValue"])
            for p in stored] == [(_POLICY, _FRACTION)], (
        f"stored policies: {[(p['PolicyName'], p['TargetTrackingScalingPolicyConfiguration']['TargetValue']) for p in stored]!r}"
    )
    _poll_until(lambda: _alarm_names(cw, alarm_prefix), lambda found: len(found) == 2,
                timeout_s=60, description="the accepted policy's two alarms in CloudWatch")


def _alarm_names(cw, prefix):
    names = []
    for page in cw.get_paginator("describe_alarms").paginate(AlarmNamePrefix=prefix):
        names.extend(a["AlarmName"] for a in page["MetricAlarms"])
    return names


def _delete_alarms(cw, prefix):
    left = _alarm_names(cw, prefix)
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
