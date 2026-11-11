"""xsvc-lambda-2-kinesis-esm-retry-exhaustion-drops-poison-batch-after-two-attempts."""
from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-lambda-2-kinesis-esm-retry-exhaustion-drops-poison-batch-after-two-attempts"
GROUP = "error-propagation"
SERVICES = ["dynamodb", "kinesis", "lambda"]

_POISON = 1
_FIRST = [0, _POISON, 2]           # one batch: the poison plus two healthy siblings
_AFTER = [10, 11, 12]              # written only after the first failed attempt is observed
_MAX_RETRIES = 1                   # => exactly 2 total attempts
_MAX_RECORD_AGE_S = 3600           # far beyond the run, so the RETRY bound is the one that fires
_EFFECT_BUDGET_S = 200


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """With MaximumRetryAttempts=1 (and a far longer MaximumRecordAgeInSeconds) a Kinesis mapping invokes an
    always-failing batch exactly twice with the identical batch, then discards it with its healthy siblings
    and delivers the records written behind it.
    """
    ddb = ctx.client("dynamodb")
    sink = _create_table(ctx, "audit")
    ddb.put_item(TableName=sink["name"], Item={"pk": {"S": "log"}, "entries": {"L": []}})
    stream = _create_stream(ctx)

    code = """
    import base64, json, os
    import boto3
    ddb = boto3.client("dynamodb")
    SINK_TABLE = os.environ["SINK_TABLE"]
    POISON = int(os.environ["POISON"])

    def handler(event, context):
        ns = [json.loads(base64.b64decode(r["kinesis"]["data"]))["n"] for r in event["Records"]]
        poisoned = POISON in ns
        ddb.update_item(
            TableName=SINK_TABLE,
            Key={"pk": {"S": "log"}},
            UpdateExpression="SET #e = list_append(#e, :v)",
            ExpressionAttributeNames={"#e": "entries"},
            ExpressionAttributeValues={":v": {"L": [{"S": json.dumps({"b": ns, "ok": 0 if poisoned else 1})}]}},
        )
        if poisoned:
            raise RuntimeError(f"poison record {POISON} in batch {ns}")
        return {"processed": len(ns)}
    """
    fn = _create_lambda(
        ctx, code,
        statements=[
            {"Action": ["kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:DescribeStream",
                        "kinesis:DescribeStreamSummary", "kinesis:ListShards"],
             "Resource": stream["arn"]},
            {"Action": ["dynamodb:UpdateItem"], "Resource": sink["arn"]},
        ],
        env={"SINK_TABLE": sink["name"], "POISON": str(_POISON)},
    )

    _put_ordered_records(ctx, stream["name"], [{"n": n} for n in _FIRST])
    uuid_ = _create_esm(ctx, fn["name"], stream["arn"],
                        StartingPosition="TRIM_HORIZON",
                        BatchSize=10,
                        MaximumBatchingWindowInSeconds=0,
                        BisectBatchOnFunctionError=False,
                        MaximumRetryAttempts=_MAX_RETRIES,
                        MaximumRecordAgeInSeconds=_MAX_RECORD_AGE_S)
    esm = ctx.client("lambda").get_event_source_mapping(UUID=uuid_)
    assert (esm.get("MaximumRetryAttempts"), esm.get("MaximumRecordAgeInSeconds")) == (
        _MAX_RETRIES, _MAX_RECORD_AGE_S), (
        f"the ESM must carry the configured bounds, got MaximumRetryAttempts="
        f"{esm.get('MaximumRetryAttempts')!r} MaximumRecordAgeInSeconds="
        f"{esm.get('MaximumRecordAgeInSeconds')!r}"
    )

    def _entries():
        item = ddb.get_item(TableName=sink["name"], Key={"pk": {"S": "log"}},
                            ConsistentRead=True).get("Item")
        return [json.loads(e["S"]) for e in item["entries"]["L"]] if item else []

    _poll_until(_entries, lambda es: any(e["ok"] == 0 for e in es),
                timeout_s=_EFFECT_BUDGET_S, interval_s=4.0,
                description="the first (failing) attempt on the poison batch")
    # Written behind the poison batch: they can only be delivered once the poller gives up on it.
    _put_ordered_records(ctx, stream["name"], [{"n": n} for n in _AFTER])

    def _after_delivered(entries):
        done = {n for e in entries if e["ok"] == 1 for n in e["b"]}
        return set(_AFTER) <= done

    entries = _poll_until(
        _entries, _after_delivered, timeout_s=_EFFECT_BUDGET_S, interval_s=4.0,
        description=(f"the records {_AFTER} written behind the poison batch to be delivered -- they "
                     f"stay blocked if the ESM never discards the batch after its retry budget"),
    )
    trail = [(e["b"], e["ok"]) for e in entries]

    failing = [e["b"] for e in entries if e["ok"] == 0]
    assert len(failing) == _MAX_RETRIES + 1, (
        f"MaximumRetryAttempts={_MAX_RETRIES} means exactly {_MAX_RETRIES + 1} attempts on the "
        f"failing batch (original + {_MAX_RETRIES} retry) before it is discarded; observed "
        f"{len(failing)!r}. trail={trail!r}"
    )
    assert all(b == _FIRST for b in failing), (
        f"with BisectBatchOnFunctionError=False the retry must re-deliver the IDENTICAL batch "
        f"{_FIRST!r}; the failing attempts were {failing!r}"
    )

    ok_batches = [e["b"] for e in entries if e["ok"] == 1]
    delivered = [n for b in ok_batches for n in b]
    leaked = sorted(set(_FIRST) & set(delivered))
    assert not leaked, (
        f"discarding the batch drops EVERY record in it, healthy siblings included; yet {leaked!r} "
        f"were later delivered successfully. successful batches {ok_batches!r}"
    )
    assert delivered == _AFTER, (
        f"after the drop the ESM must move on and deliver the records behind the poison batch once, "
        f"in shard order: expected {_AFTER!r}, got {delivered!r}. trail={trail!r}"
    )
    first_ok = next(i for i, e in enumerate(entries) if e["ok"] == 1)
    last_fail = max(i for i, e in enumerate(entries) if e["ok"] == 0)
    assert last_fail < first_ok, (
        f"per-shard ordering: the records behind the poison batch may only be delivered after the "
        f"poller is done with it. trail={trail!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _err(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate holds. RAISES on timeout -- never returns the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _swallow(fn) -> None:
    """Teardown-only: an already-gone resource is fine; anything else is a named leak."""
    try:
        fn()
    except ClientError as exc:
        if _err(exc) != "ResourceNotFoundException":
            raise RuntimeError(f"teardown step failed: {exc}") from exc


def _create_table(ctx, kind: str) -> dict[str, str]:
    ddb = ctx.client("dynamodb")
    name = _xname(ctx, kind)
    resp = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _swallow(lambda: ddb.delete_table(TableName=name)))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return {"name": name, "arn": resp["TableDescription"]["TableArn"]}


def _create_stream(ctx) -> dict[str, str]:
    """A one-shard Kinesis stream (one shard = one ordered sequence, one in-flight batch)."""
    kinesis = ctx.client("kinesis")
    name = _xname(ctx, "kin")
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(lambda: _swallow(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)))
    summary = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda d: d.get("StreamStatus") == "ACTIVE",
        timeout_s=120, interval_s=3.0, description=f"Kinesis stream {name} ACTIVE",
    )
    return {"name": name, "arn": summary["StreamARN"]}


def _put_ordered_records(ctx, stream_name: str, payloads: list[dict]) -> list[str]:
    """Sequential PutRecord on ONE partition key chained through SequenceNumberForOrdering --
    the documented way to pin strict order within a shard (PutRecords does not guarantee it)."""
    kinesis = ctx.client("kinesis")
    seqs: list[str] = []
    prev = None
    for payload in payloads:
        kwargs: dict[str, Any] = {"StreamName": stream_name, "PartitionKey": "one-key",
                                  "Data": json.dumps(payload).encode()}
        if prev is not None:
            kwargs["SequenceNumberForOrdering"] = prev
        prev = kinesis.put_record(**kwargs)["SequenceNumber"]
        seqs.append(prev)
    return seqs


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=p)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if _err(exc) != "NoSuchEntity":
            raise RuntimeError(f"IAM role {role_name}: {exc}") from exc


def _reap_log_group(ctx, fn_name: str) -> None:
    """delete_function leaves /aws/lambda/<fn>, and a buffered flush can RECREATE it after a
    delete, so reap in a loop until it stays absent for three consecutive reads."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"
    deadline = time.monotonic() + 45
    absent = 0
    while time.monotonic() < deadline:
        try:
            logs.delete_log_group(logGroupName=group)
            absent = 0
        except ClientError as exc:
            if _err(exc) != "ResourceNotFoundException":
                raise RuntimeError(f"log group {group}: {exc}") from exc
            absent += 1
            if absent >= 3:
                return
        time.sleep(5)
    raise RuntimeError(f"log group {group} kept reappearing after delete")


def _create_lambda(ctx, handler_code: str, *, statements: list[dict], env: dict) -> dict[str, str]:
    """A Lambda plus an execution role scoped to `statements`; logs are always allowed."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    policy = [{"Effect": "Allow",
               "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
               "Resource": "arn:aws:logs:*:*:*"}]
    policy += [{"Effect": "Allow", **s} for s in statements]
    role_name = _xname(ctx, "role")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy}))

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code).strip() + "\n")
    name = _xname(ctx, "fn")
    # Registered BEFORE the create so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))

    def _attempt():
        try:
            return lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.handler", Code={"ZipFile": buf.getvalue()},
                Timeout=30, MemorySize=128, Environment={"Variables": env},
                Tags=dict(_MANAGED_TAGS),
            )
        except ClientError as exc:
            if _err(exc) == "InvalidParameterValueException":   # fresh role not yet assumable
                return None
            raise

    created = _poll_until(_attempt, lambda r: r is not None, timeout_s=90, interval_s=4.0,
                          description=f"CreateFunction {name} past the role-propagation window")
    ctx.on_cleanup(lambda: _swallow(lambda: lam.delete_function(FunctionName=name)))
    _poll_until(lambda: lam.get_function_configuration(FunctionName=name),
                lambda c: c.get("State") == "Active", timeout_s=120, interval_s=3.0,
                description=f"Lambda {name} State Active")
    return {"name": name, "arn": created["FunctionArn"]}


def _delete_esm(ctx, uuid_: str) -> None:
    """An ESM still Creating/Enabling refuses deletion with ResourceInUseException; retry, bounded."""
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            lam.delete_event_source_mapping(UUID=uuid_)
            return
        except ClientError as exc:
            if _err(exc) == "ResourceNotFoundException":
                return
            if _err(exc) != "ResourceInUseException":
                raise RuntimeError(f"event source mapping {uuid_}: {exc}") from exc
        time.sleep(5)
    raise RuntimeError(f"event source mapping {uuid_} still in use after 90s")


def _create_esm(ctx, fn_name: str, source_arn: str, **params) -> str:
    """CreateEventSourceMapping validates the execution role's source (and destination)
    permissions, which a fresh role may not yet carry -- retry that window, bounded.
    Deliberately does NOT wait for Enabled: the downstream effect wait covers activation."""
    lam = ctx.client("lambda")
    seen: list[str] = []

    def _attempt():
        try:
            return lam.create_event_source_mapping(FunctionName=fn_name, EventSourceArn=source_arn,
                                                   Enabled=True, **params)
        except ClientError as exc:
            if _err(exc) == "InvalidParameterValueException":
                seen.append(str(exc))
                return None
            raise

    try:
        resp = _poll_until(_attempt, lambda r: r is not None, timeout_s=90, interval_s=5.0,
                           description="CreateEventSourceMapping past IAM propagation")
    except AssertionError as exc:
        raise AssertionError(f"{exc}; last refusal {seen[-1:]!r}") from None
    ctx.on_cleanup(lambda: _delete_esm(ctx, resp["UUID"]))
    return resp["UUID"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
