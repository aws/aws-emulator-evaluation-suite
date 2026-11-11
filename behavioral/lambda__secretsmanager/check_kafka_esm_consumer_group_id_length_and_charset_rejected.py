"""kafka-esm-consumer-group-id-length-and-charset-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kafka-esm-consumer-group-id-length-and-charset-rejected"
GROUP = "validation"
SERVICES = ["lambda", "secretsmanager"]

#: A mapping leaves Creating on its own schedule and cannot be deleted before it does.
_TRANSITIONAL = ("Creating", "Enabling", "Disabling", "Updating", "Deleting")
_SETTLE_WAIT_S = 600
#: RFC 2606 reserves .invalid: the bootstrap server can never resolve, so nothing is ever polled.
BOOTSTRAP = "sim2real.invalid:9092"
TOPIC = "sim2real-topic"
#: Lambda's URI shape: 1-200 chars, charset '[ a-zA-Z0-9-/*:_+=.@-]'.
_LONG_ID = "g" * 201
_BAD_CHARSET_ID = "sim2real!group#id"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ConsumerGroupId over 200 chars or outside its charset is refused with the exact Smithy
    ValidationException for both self-managed and Amazon MSK Kafka event sources, before any
    cluster is ever contacted, while a conforming id is accepted and echoed back.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/with-kafka.html#services-smaa-topic-add
    """
    lam = ctx.client("lambda")
    secret_arn = _secret(ctx)
    role_arn, role_name = _execution_role(ctx, secret_arn)
    fn = ctx.unique_name("sim2real-behav-kgid-")
    created = _function(ctx, FunctionName=fn, Runtime="python3.13", Handler="index.handler",
                        Role=role_arn, Code={"ZipFile": _noop_zip()}, MemorySize=128, Timeout=10)
    msk_arn = (f"arn:aws:kafka:{ctx.region}:{ctx.account}:cluster/"
               f"{ctx.unique_name('sim2real-behav-kgid-cl')}/"
               "00000000-0000-0000-0000-000000000000-1")

    baseline = len(_mappings(lam, fn))

    # Positive control: a conforming ConsumerGroupId is honored, not silently replaced.
    valid_id = ctx.unique_name("sim2real-behav-cg-")
    positive = _create_mapping(ctx, lam, dict(
        FunctionName=fn, Topics=[TOPIC], StartingPosition="LATEST",
        SelfManagedEventSource={"Endpoints": {"KAFKA_BOOTSTRAP_SERVERS": [BOOTSTRAP]}},
        SourceAccessConfigurations=[{"Type": "BASIC_AUTH", "URI": secret_arn}],
        SelfManagedKafkaEventSourceConfig={"ConsumerGroupId": valid_id}))
    assert positive["SelfManagedKafkaEventSourceConfig"]["ConsumerGroupId"] == valid_id, (
        f"expected the accepted mapping to echo ConsumerGroupId {valid_id!r}, got "
        f"{positive['SelfManagedKafkaEventSourceConfig']!r}")
    _delete_mapping(lam, positive["UUID"], ctx)
    assert len(_mappings(lam, fn)) == baseline, (
        "function still lists a mapping after the positive control was deleted")

    for config_key, path, value, constraint in (
        ("SelfManagedKafkaEventSourceConfig", "selfManagedKafkaEventSourceConfig.consumerGroupId",
         _LONG_ID, "Member must have length less than or equal to 200"),
        ("SelfManagedKafkaEventSourceConfig", "selfManagedKafkaEventSourceConfig.consumerGroupId",
         _BAD_CHARSET_ID,
         r"Member must satisfy regular expression pattern: [ a-zA-Z0-9-\/*:_+=.@-]*"),
        ("AmazonManagedKafkaEventSourceConfig", "amazonManagedKafkaEventSourceConfig.consumerGroupId",
         _LONG_ID, "Member must have length less than or equal to 200"),
        ("AmazonManagedKafkaEventSourceConfig", "amazonManagedKafkaEventSourceConfig.consumerGroupId",
         _BAD_CHARSET_ID,
         r"Member must satisfy regular expression pattern: [ a-zA-Z0-9-\/*:_+=.@-]*"),
    ):
        request = dict(FunctionName=fn, Topics=[TOPIC], StartingPosition="LATEST",
                       **{config_key: {"ConsumerGroupId": value}})
        if config_key == "SelfManagedKafkaEventSourceConfig":
            request["SelfManagedEventSource"] = {"Endpoints": {"KAFKA_BOOTSTRAP_SERVERS": [BOOTSTRAP]}}
        else:
            request["EventSourceArn"] = msk_arn
        code, msg = _error(lambda req=request: lam.create_event_source_mapping(**req))
        assert code == "ValidationException", (
            f"{config_key} ConsumerGroupId {value!r} refused with {code!r}: {msg!r}")
        expected = f"1 validation error detected: Value '{value}' at '{path}' failed to satisfy constraint: {constraint}"
        assert msg == expected, f"expected {expected!r}, got {msg!r}"
        assert len(_mappings(lam, fn)) == baseline, (
            f"a rejected {config_key} request left a mapping behind for value {value!r}")


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
    name = ctx.unique_name("sim2real-behav-kgid-secret-")
    arn = sm.create_secret(Name=name, SecretString=json.dumps(
        {"username": "sim2real", "password": ctx.unique_name("pw-")}),
        Tags=[{"Key": "sim2real", "Value": CHECK}])["ARN"]
    ctx.on_cleanup(_teardown(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True),
                            "ResourceNotFoundException"))
    return arn


def _execution_role(ctx, secret_arn) -> tuple:
    """A Lambda execution role that may read ``secret_arn`` and grants nothing else."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-kgid-role-")
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
