"""msk-esm-topics-list-too-long-rejected."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "msk-esm-topics-list-too-long-rejected"
GROUP = "validation"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventSourceMapping for an MSK cluster rejects a Topics list of more than one
    entry before any cluster lookup; the same request with a single topic instead reaches
    the role's DescribeClusterV2 check, and neither attempt leaves a mapping.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/with-msk.html
    """
    lam = ctx.client("lambda")
    role_arn = _execution_role(ctx)
    fn = ctx.unique_name("sim2real-behav-msktopics-")
    created = _function(ctx, FunctionName=fn, Runtime="python3.12", Handler="index.handler",
                        Role=role_arn, Code={"ZipFile": _noop_zip()}, MemorySize=128, Timeout=10)
    partition = created["FunctionArn"].split(":")[1]
    cluster = (f"arn:{partition}:kafka:{ctx.region}:{ctx.account}:cluster/"
               f"{ctx.unique_name('sim2real-absent-')}/{uuid.uuid4()}-2")
    topic1 = ctx.unique_name("sim2real-topic-a-")
    topic2 = ctx.unique_name("sim2real-topic-b-")
    too_many_refusal = ("ValidationException", (
        f"1 validation error detected: Value '[{topic1}, {topic2}]' at 'topics' failed to "
        f"satisfy constraint: Member must have length less than or equal to 1"))
    role_refusal = ("InvalidParameterValueException", (
        f"Cannot access cluster {cluster}. Please ensure the role can perform the "
        f"DescribeClusterV2 (recommended) or DescribeCluster and GetBootstrapBrokers actions on "
        f"your cluster in IAM."))

    def attempt(topics):
        return _error(lambda: lam.create_event_source_mapping(
            FunctionName=fn, EventSourceArn=cluster, Topics=topics, StartingPosition="LATEST"))

    got = attempt([topic1, topic2])
    assert got == too_many_refusal, f"two topics were refused with {got!r}"
    got = attempt([topic1])
    assert got == role_refusal, f"one topic was refused with {got!r}"
    left = _mappings(lam, fn)
    assert left == [], f"the refused requests left {left!r}"


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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll(ctx, probe, done, *, cap_s, interval_s, what):
    """``probe()`` until ``done(result)`` under a deadline capped by the run budget; raises
    TimeoutError naming ``what`` and the last result."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out after {timeout_s:.0f}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _execution_role(ctx) -> str:
    """A Lambda execution role with no permissions, so no function of this check ever creates a
    log group that could outlive it; returns its ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


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

    out = _poll(ctx, create, lambda r: r is not None, cap_s=90, interval_s=3,
                what="CreateFunction accepts the fresh execution role")
    name = kwargs["FunctionName"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(ctx, lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed")
                 and c.get("LastUpdateStatus", "Successful") != "InProgress",
                 cap_s=300, interval_s=2, what=f"function {name} settles")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
