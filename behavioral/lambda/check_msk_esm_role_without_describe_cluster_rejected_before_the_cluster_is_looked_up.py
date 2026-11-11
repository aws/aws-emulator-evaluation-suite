"""msk-esm-role-without-describe-cluster-rejected-before-the-cluster-is-looked-up."""
from __future__ import annotations

import base64
import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "msk-esm-role-without-describe-cluster-rejected-before-the-cluster-is-looked-up"
GROUP = "permission-boundary"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventSourceMapping for an MSK cluster whose execution role cannot describe it fails
    InvalidParameterValueException naming the cluster; granting only kafka:DescribeClusterV2 moves
    the same request to ResourceNotFoundException for the absent cluster, and no mapping remains.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/with-msk-permissions.html
    """
    lam = ctx.client("lambda")
    role_arn, role_name = _execution_role(ctx)
    fn = ctx.unique_name("sim2real-behav-mskesm-")
    created = _function(ctx, FunctionName=fn, Runtime="python3.12", Handler="index.handler",
                        Role=role_arn, Code={"ZipFile": _noop_zip()}, MemorySize=128, Timeout=10)
    partition = created["FunctionArn"].split(":")[1]
    cluster = (f"arn:{partition}:kafka:{ctx.region}:{ctx.account}:cluster/"
               f"{ctx.unique_name('sim2real-absent-')}/{uuid.uuid4()}-2")
    role_refusal = ("InvalidParameterValueException", (
        f"Cannot access cluster {cluster}. Please ensure the role can perform the "
        f"DescribeClusterV2 (recommended) or DescribeCluster and GetBootstrapBrokers actions on "
        f"your cluster in IAM."))
    absent = ("ResourceNotFoundException",
              f"The cluster resource: {cluster} you requested does not exist.")

    def attempt():
        return _error(lambda: lam.create_event_source_mapping(
            FunctionName=fn, EventSourceArn=cluster, Topics=["sim2real-topic"],
            StartingPosition="LATEST"))

    got = attempt()
    assert got == role_refusal, f"a role without kafka:DescribeClusterV2 was refused with {got!r}"
    assert _mappings(lam, fn) == [], f"the refused request left {_mappings(lam, fn)!r}"

    _set_policy(ctx, role_name, [{"Effect": "Allow", "Action": "kafka:DescribeClusterV2",
                                  "Resource": "*"}])
    got = _poll(attempt, lambda r: r != role_refusal, timeout_s=120, interval_s=5,
                what="the granted kafka:DescribeClusterV2 reaches Lambda's role check")
    assert got == absent, f"with kafka:DescribeClusterV2 the same request was refused with {got!r}"
    assert _mappings(lam, fn) == [], f"the cluster-absent refusal left {_mappings(lam, fn)!r}"


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
