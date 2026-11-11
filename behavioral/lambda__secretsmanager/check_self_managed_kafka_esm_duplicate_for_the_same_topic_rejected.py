"""self-managed-kafka-esm-duplicate-for-the-same-topic-rejected."""
from __future__ import annotations

import base64
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "self-managed-kafka-esm-duplicate-for-the-same-topic-rejected"
GROUP = "validation"
SERVICES = ["lambda", "secretsmanager"]

#: A mapping leaves Creating on its own schedule and cannot be deleted before it does.
ESM_SETTLE_WAIT_S = 600
#: RFC 2606 reserves .invalid: the bootstrap server can never resolve, so nothing is ever polled.
BOOTSTRAP = "sim2real.invalid:9092"
TOPIC = "sim2real-topic"
_TRANSITIONAL = ("Creating", "Enabling", "Disabling", "Updating", "Deleting")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second self-managed Kafka mapping for the same function, bootstrap server and topic is refused
    with ResourceConflictException naming the existing mapping's UUID, the function keeps exactly
    one mapping, and after deleting it the identical request is accepted.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/with-kafka.html
    """
    lam = ctx.client("lambda")
    sm = ctx.client("secretsmanager")
    secret = sm.create_secret(Name=ctx.unique_name("sim2real-behav-kafka-auth-"),
                              SecretString=json.dumps({"username": "sim2real",
                                                       "password": ctx.unique_name("pw-")}),
                              Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_teardown(lambda: sm.delete_secret(SecretId=secret["ARN"],
                                                      ForceDeleteWithoutRecovery=True),
                             "ResourceNotFoundException"))
    role_arn, _ = _execution_role(ctx, [{"Effect": "Allow",
                                         "Action": "secretsmanager:GetSecretValue",
                                         "Resource": secret["ARN"]}])
    fn = ctx.unique_name("sim2real-behav-kafkaesm-")
    created = _function(ctx, FunctionName=fn, Runtime="python3.12", Handler="index.handler",
                        Role=role_arn, Code={"ZipFile": _noop_zip()}, MemorySize=128, Timeout=10)
    request = dict(FunctionName=fn, Topics=[TOPIC], StartingPosition="LATEST",
                   SelfManagedEventSource={"Endpoints": {"KAFKA_BOOTSTRAP_SERVERS": [BOOTSTRAP]}},
                   SourceAccessConfigurations=[{"Type": "BASIC_AUTH", "URI": secret["ARN"]}])

    first = _create_mapping(ctx, lam, request)
    assert (first["Topics"], first["SelfManagedEventSource"]) == (
        [TOPIC], {"Endpoints": {"KAFKA_BOOTSTRAP_SERVERS": [BOOTSTRAP]}}), (
        f"the accepted mapping echoes {first['Topics']!r} {first['SelfManagedEventSource']!r}")

    code, msg = _error(lambda: lam.create_event_source_mapping(**request))
    assert code == "ResourceConflictException", f"duplicate refused with {code!r}: {msg!r}"
    assert msg == (
        f'An event source mapping with event source ("{BOOTSTRAP}"), function '
        f'("{created["FunctionArn"]}"), topics ("{TOPIC}") already exists. Please update or '
        f'delete the existing mapping with UUID {first["UUID"]}'), f"duplicate refused with {msg!r}"
    listed = [m["UUID"] for m in _mappings(lam, fn)]
    assert listed == [first["UUID"]], f"after the refusal the function lists {listed!r}"

    _delete_mapping(lam, first["UUID"])
    again = _create_mapping(ctx, lam, request)
    listed = [m["UUID"] for m in _mappings(lam, fn)]
    assert listed == [again["UUID"]] and again["UUID"] != first["UUID"], (
        f"after deleting {first['UUID']} the re-created mapping is {again['UUID']} and the "
        f"function lists {listed!r}")


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

    esm = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=5,
                what="the fresh role's secret access reaches Lambda")
    ctx.on_cleanup(lambda: _delete_mapping(lam, esm["UUID"]))
    return esm


def _delete_mapping(lam, uuid) -> None:
    """Delete a mapping once it leaves its transitional states, and wait until it is gone."""

    def settled():
        try:
            return lam.get_event_source_mapping(UUID=uuid)["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return "gone"
            raise

    state = _poll(settled, lambda s: s not in _TRANSITIONAL, timeout_s=ESM_SETTLE_WAIT_S,
                  interval_s=5, what=f"mapping {uuid} leaves its transitional states")
    if state != "gone":
        _teardown(lambda: lam.delete_event_source_mapping(UUID=uuid),
                  "ResourceNotFoundException")()
        _poll(settled, lambda s: s == "gone", timeout_s=ESM_SETTLE_WAIT_S, interval_s=5,
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


def _set_policy(ctx, role_name, statements) -> None:
    iam = ctx.client("iam")
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))


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


def _poll(probe, done, *, timeout_s, interval_s, what):
    """``probe()`` until ``done(result)``; raises naming ``what`` and the last result on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _execution_role(ctx, statements=None) -> tuple:
    """A Lambda execution role holding exactly ``statements`` and no logs: grant, so no function
    of this check ever creates a log group that could outlive it (LogType=Tail needs none)."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
        "NoSuchEntity"))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": statements}))
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

    out = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=3,
                what="CreateFunction accepts the fresh execution role")
    name = kwargs["FunctionName"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    _wait_active(lam, name)
    return out


def _wait_active(lam, name, qualifier=None) -> dict:
    args = {"FunctionName": name}
    if qualifier:
        args["Qualifier"] = qualifier
    conf = _poll(lambda: lam.get_function_configuration(**args),
                 lambda c: c.get("State", "Active") in ("Active", "Failed")
                 and c.get("LastUpdateStatus", "Successful") != "InProgress",
                 timeout_s=300, interval_s=2, what=f"function {name} settles")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return conf


def _invoke(lam, name, payload: bytes, qualifier=None) -> dict:
    """One RequestResponse invoke with the log tail: status, error flag, raw payload, request id."""
    args = {"FunctionName": name, "InvocationType": "RequestResponse", "LogType": "Tail",
            "Payload": payload}
    if qualifier:
        args["Qualifier"] = qualifier
    resp = lam.invoke(**args)
    return {"status": resp["StatusCode"], "error": resp.get("FunctionError"),
            "raw": resp["Payload"].read(),
            "log": base64.b64decode(resp.get("LogResult", "")).decode("utf-8", "replace"),
            "request_id": resp["ResponseMetadata"]["RequestId"]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
