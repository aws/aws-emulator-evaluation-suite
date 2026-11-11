"""lambda-latest-and-unqualified-targets-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-latest-and-unqualified-targets-rejected"
GROUP = "scalable-targets"
SERVICES = ["application-autoscaling"]

_NS = "lambda"
_DIM = "lambda:function:ProvisionedConcurrency"
_ALIAS = "live"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Provisioned concurrency scales a version or alias, so RegisterScalableTarget refuses $LATEST
    and unqualified function ids, each with its own ValidationException, registering neither; the
    published version registers.
    """
    aas = ctx.client("application-autoscaling")
    function, version = _function_with_alias(ctx, _ALIAS)
    latest_id = f"function:{function}:$LATEST"
    bare_id = f"function:{function}"
    version_id = f"function:{function}:{version}"
    for rid in (latest_id, bare_id, version_id):
        ctx.on_cleanup(lambda rid=rid: _ignore_missing(
            lambda: aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=rid,
                                                   ScalableDimension=_DIM),
            "ObjectNotFoundException", "ValidationException"))

    code, message = _error(lambda: aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=latest_id, ScalableDimension=_DIM,
        MinCapacity=0, MaxCapacity=2))
    assert (code, message) == ("ValidationException",
                               "$LATEST is not a supported qualifier for Auto Scaling"), (
        f"registering the $LATEST qualifier was refused with {code!r}: {message!r}"
    )

    code, message = _error(lambda: aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=bare_id, ScalableDimension=_DIM,
        MinCapacity=0, MaxCapacity=2))
    assert (code, message) == ("ValidationException",
                               "Unsupported service namespace, resource type or scalable "
                               "dimension"), (
        f"registering an unqualified function was refused with {code!r}: {message!r}"
    )

    stored = _targets(aas)
    assert latest_id not in stored and bare_id not in stored, (
        "a refused Lambda resource id is registered anyway"
    )

    # Positive control: the published version of the same function registers.
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=version_id,
                                 ScalableDimension=_DIM, MinCapacity=0, MaxCapacity=2)
    stored = _targets(aas)
    assert stored.get(version_id) == (0, 2), (
        f"the published version registered with bounds {stored.get(version_id)!r}, expected (0, 2)"
    )


def _targets(aas):
    """{resource id: (min, max)} for this namespace and dimension, every page."""
    out = {}
    for page in aas.get_paginator("describe_scalable_targets").paginate(
            ServiceNamespace=_NS):
        for t in page["ScalableTargets"]:
            if t["ScalableDimension"] == _DIM:
                    out[t["ResourceId"]] = (t["MinCapacity"], t["MaxCapacity"])
    return out


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
