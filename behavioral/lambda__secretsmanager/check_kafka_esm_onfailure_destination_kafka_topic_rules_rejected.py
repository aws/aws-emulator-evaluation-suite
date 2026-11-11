"""kafka-esm-onfailure-destination-kafka-topic-rules-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kafka-esm-onfailure-destination-kafka-topic-rules-rejected"
GROUP = "validation"
SERVICES = ["lambda", "secretsmanager"]

_TRANSITIONAL = ("Creating", "Enabling", "Disabling", "Updating", "Deleting")
_SETTLE_WAIT_S = 600
#: RFC 2606 reserves .invalid: the bootstrap server can never resolve, so nothing is ever polled.
BOOTSTRAP = "sim2real.invalid:9092"
TOPIC = "sim2real-topic"
DLT_TOPIC = "sim2real-dlt-topic"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A kafka:// on-failure destination is refused outside provisioned mode, and refused when it
    names the same topic as the source (recursion); naming a distinct topic in provisioned mode is
    accepted and echoed back.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/kafka-on-failure-destination.html
    """
    lam = ctx.client("lambda")
    secret_arn = _secret(ctx)
    role_arn, _ = _execution_role(ctx, secret_arn)
    fn = ctx.unique_name("sim2real-behav-kdlt-")
    _function(ctx, FunctionName=fn, Runtime="python3.13", Handler="index.handler",
             Role=role_arn, Code={"ZipFile": _noop_zip()}, MemorySize=128, Timeout=10)
    sac = [{"Type": "BASIC_AUTH", "URI": secret_arn}]
    ppc = {"MinimumPollers": 1, "MaximumPollers": 1}

    baseline = len(_mappings(lam, fn))

    no_provisioned_req = dict(
        FunctionName=fn, Topics=[TOPIC], StartingPosition="LATEST",
        SelfManagedEventSource={"Endpoints": {"KAFKA_BOOTSTRAP_SERVERS": [BOOTSTRAP]}},
        SourceAccessConfigurations=sac,
        DestinationConfig={"OnFailure": {"Destination": f"kafka://{DLT_TOPIC}"}})
    code, msg = _error(lambda: lam.create_event_source_mapping(**no_provisioned_req))
    assert code == "InvalidParameterValueException", (
        f"kafka:// destination outside provisioned mode refused with {code!r}: {msg!r}")
    expected = (
        "Kafka as a DestinationConfig is only available for provisioned mode. To use Kafka as "
        "a DestinationConfig, enable provisioned mode by specifying MinimumPollers in "
        "ProvisionedPollerConfig, and try again.")
    assert msg == expected, f"expected {expected!r}, got {msg!r}"

    recursion_req = dict(
        FunctionName=fn, Topics=[TOPIC], StartingPosition="LATEST",
        SelfManagedEventSource={"Endpoints": {"KAFKA_BOOTSTRAP_SERVERS": [BOOTSTRAP]}},
        SourceAccessConfigurations=sac, ProvisionedPollerConfig=ppc,
        DestinationConfig={"OnFailure": {"Destination": f"kafka://{TOPIC}"}})
    code, msg = _error(lambda: lam.create_event_source_mapping(**recursion_req))
    assert code == "InvalidParameterValueException", (
        f"kafka:// destination naming the source topic refused with {code!r}: {msg!r}")
    expected = f"The destination topic name cannot be the same as the source topic name: {TOPIC}."
    assert msg == expected, f"expected {expected!r}, got {msg!r}"

    assert len(_mappings(lam, fn)) == baseline, (
        "a rejected kafka:// destination request left a mapping behind")

    # Positive control: provisioned mode plus a distinct destination topic is accepted.
    positive = _create_mapping(ctx, lam, dict(
        FunctionName=fn, Topics=[TOPIC], StartingPosition="LATEST",
        SelfManagedEventSource={"Endpoints": {"KAFKA_BOOTSTRAP_SERVERS": [BOOTSTRAP]}},
        SourceAccessConfigurations=sac, ProvisionedPollerConfig=ppc,
        DestinationConfig={"OnFailure": {"Destination": f"kafka://{DLT_TOPIC}"}}))
    assert positive["DestinationConfig"] == {"OnFailure": {"Destination": f"kafka://{DLT_TOPIC}"}}, (
        f"expected the accepted destination echoed verbatim, got {positive['DestinationConfig']!r}")
    _delete_mapping(lam, positive["UUID"], ctx)
    assert len(_mappings(lam, fn)) == baseline, (
        "function still lists a mapping after the positive control was deleted")


# ===== helpers =====
def _create_mapping(ctx, lam, request) -> dict:
    """CreateEventSourceMapping through the role-propagation window; its delete registered."""

    def create():
        try:
            return lam.create_event_source_mapping(**request)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "InvalidParameterValueException" and "Cannot access" in err.get(
                    "Message", ""):
                return None
            raise

    esm = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=5, ctx=ctx,
               what="the fresh role's secret access reaches Lambda")
    ctx.on_cleanup(lambda: _delete_mapping(lam, esm["UUID"]))
    return esm


def _delete_mapping(lam, uuid, ctx=None) -> None:
    """Delete a mapping once it leaves its transitional states, and wait until it is gone; the
    waits are capped by the run budget when ``ctx`` is given (the body), not in a teardown."""

    def settled():
        try:
            return lam.get_event_source_mapping(UUID=uuid)["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return "gone"
            raise

    state = _poll(settled, lambda s: s not in _TRANSITIONAL, timeout_s=_SETTLE_WAIT_S,
                 interval_s=5, ctx=ctx, what=f"mapping {uuid} leaves its transitional states")
    if state != "gone":
        _teardown(lambda: lam.delete_event_source_mapping(UUID=uuid), "ResourceNotFoundException")()
        _poll(settled, lambda s: s == "gone", timeout_s=_SETTLE_WAIT_S, interval_s=5, ctx=ctx,
             what=f"mapping {uuid} is deleted")


def _error(fn) -> tuple:
    """(code, message) of the ClientError ``fn()`` raises; an unexpected success raises."""
    try:
        out = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, the call succeeded: {out!r}")


def _mappings(lam, fn) -> list:
    out = []
    for page in lam.get_paginator("list_event_source_mappings").paginate(FunctionName=fn):
        out.extend(page["EventSourceMappings"])
    return out


_NOOP = """\
def handler(event, context):
    return {"ok": True}
"""


def _noop_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _NOOP)
    return buf.getvalue()


def _secret(ctx) -> str:
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-kdlt-secret-")
    arn = sm.create_secret(Name=name, SecretString=json.dumps(
        {"username": "sim2real", "password": ctx.unique_name("pw-")}),
        Tags=[{"Key": "sim2real", "Value": CHECK}])["ARN"]
    ctx.on_cleanup(_teardown(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True),
                            "ResourceNotFoundException"))
    return arn


def _execution_role(ctx, secret_arn) -> tuple:
    """A Lambda execution role that may read ``secret_arn`` and grants nothing else."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-kdlt-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"), "NoSuchEntity"))
    iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}]}))
    return arn, name


def _function(ctx, **kwargs) -> dict:
    """CreateFunction through the role-propagation window, its delete registered, then Active."""
    lam = ctx.client("lambda")
    kwargs.setdefault("Tags", {"sim2real": CHECK})

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")):
                return None
            raise

    out = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=3, ctx=ctx,
               what="CreateFunction accepts the fresh execution role")
    name = kwargs["FunctionName"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                            "ResourceNotFoundException"))
    _wait_active(ctx, lam, name)
    return out


def _wait_active(ctx, lam, name) -> dict:
    conf = _poll(lambda: lam.get_function_configuration(FunctionName=name),
                lambda c: c.get("State", "Active") in ("Active", "Failed")
                and c.get("LastUpdateStatus", "Successful") != "InProgress",
                timeout_s=300, interval_s=2, what=f"function {name} settles", ctx=ctx)
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return conf


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll(probe, done, *, timeout_s, interval_s, what, ctx=None):
    """``probe()`` until ``done(result)``; raises TimeoutError naming ``what`` and the last result
    when ``timeout_s``, capped by the run budget when ``ctx`` is given, runs out."""
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out after {timeout_s:.0f}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
