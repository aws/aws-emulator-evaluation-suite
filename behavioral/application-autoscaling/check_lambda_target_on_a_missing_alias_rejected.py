"""lambda-target-on-a-missing-alias-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-target-on-a-missing-alias-rejected"
GROUP = "scalable-targets"
SERVICES = ["application-autoscaling"]

_NS = "lambda"
_DIM = "lambda:function:ProvisionedConcurrency"
_ALIAS = "live"
_MISSING = "never-created"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterScalableTarget refuses a missing alias on an existing function with a
    ValidationException naming the resource, dimension and alias ARN, and registers nothing;
    the function's real alias registers.
    """
    aas = ctx.client("application-autoscaling")
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    function, _version = _function_with_alias(ctx, _ALIAS)
    missing_id = f"function:{function}:{_MISSING}"
    alias_id = f"function:{function}:{_ALIAS}"
    for rid in (missing_id, alias_id):
        ctx.on_cleanup(lambda rid=rid: _ignore_missing(
            lambda: aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=rid,
                                                   ScalableDimension=_DIM),
            "ObjectNotFoundException"))

    code, message = _error(lambda: aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=missing_id, ScalableDimension=_DIM,
        MinCapacity=0, MaxCapacity=2))
    assert code == "ValidationException", f"a missing alias was refused with {code!r}"
    alias_arn = f"arn:{partition}:lambda:{ctx.region}:{ctx.account}:function:{function}:{_MISSING}"
    expected = (f"Validation failed for resource: {missing_id}, scalable dimension: {_DIM}. "
                f"Reason: Cannot find alias arn: {alias_arn}")
    assert message == expected, f"refusal message {message!r}, expected {expected!r}"
    assert _bounds(aas, missing_id) is None, "the missing alias is registered anyway"

    # Positive control: the alias that exists on the same function registers.
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=alias_id,
                                 ScalableDimension=_DIM, MinCapacity=0, MaxCapacity=2)
    assert _bounds(aas, alias_id) == (0, 2), (
        f"the existing alias registered with bounds {_bounds(aas, alias_id)!r}, expected (0, 2)"
    )


def _bounds(aas, resource_id):
    found = []
    for page in aas.get_paginator("describe_scalable_targets").paginate(
            ServiceNamespace=_NS, ResourceIds=[resource_id], ScalableDimension=_DIM):
        found.extend((t["MinCapacity"], t["MaxCapacity"]) for t in page["ScalableTargets"])
    assert len(found) <= 1, f"{len(found)} targets share one resource id"
    return found[0] if found else None


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
