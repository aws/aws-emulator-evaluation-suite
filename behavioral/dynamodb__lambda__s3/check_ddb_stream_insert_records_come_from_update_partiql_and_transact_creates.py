"""ddb-stream-insert-records-come-from-update-partiql-and-transact-creates."""

from __future__ import annotations

import base64
import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddb-stream-insert-records-come-from-update-partiql-and-transact-creates"

GROUP = "event-propagation"

SERVICES = ["dynamodb", "lambda"]

_HANDLER = r'''
import base64, json, os
import boto3
ddb = boto3.client("dynamodb")


def canon(v):
    """A stream attribute value as JSON with set members sorted (sets keep no order)."""
    if isinstance(v, dict):
        return {k: (sorted(x) if k in ("SS", "NS", "BS") else canon(x)) for k, x in v.items()}
    if isinstance(v, list):
        return [canon(x) for x in v]
    return v


def lambda_handler(event, context):
    for record in event["Records"]:
        body = record["dynamodb"]
        keys = body["Keys"]
        sink_key = "#".join([keys["pk"]["S"]] + ([keys["sk"]["N"]] if "sk" in keys else []) + [record["eventName"]])
        ddb.put_item(TableName=os.environ["SINK"], Item={
            "pk": {"S": sink_key},
            "event": {"S": record["eventName"]},
            "source_arn": {"S": record["eventSourceARN"]},
            "view": {"S": body.get("StreamViewType", "")},
            "keys": {"S": json.dumps(canon(keys), sort_keys=True)},
            "new_image": {"S": json.dumps(canon(body["NewImage"]), sort_keys=True) if "NewImage" in body else "-"},
            "old_image": {"S": json.dumps(canon(body["OldImage"]), sort_keys=True) if "OldImage" in body else "-"},
        })
    return {"ok": True}
'''


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Items created by UpdateItem, a PartiQL INSERT and TransactWriteItems each reach the function as an
    INSERT record with the exact NewImage, and a later update of an existing item as a MODIFY with
    both images; no record of another key or event name is delivered.
    """
    table = _create_table(ctx, stream=True, stream_view_type="NEW_AND_OLD_IMAGES")
    sink = _create_table(ctx)
    fn = _create_lambda(
        ctx,
        _HANDLER,
        permissions=[
            {
                "Action": [
                    "dynamodb:GetRecords",
                    "dynamodb:GetShardIterator",
                    "dynamodb:DescribeStream",
                    "dynamodb:ListStreams",
                ],
                "Resource": table["arn"] + "/stream/*",
            },
            {"Action": ["dynamodb:PutItem"], "Resource": sink["arn"]},
        ],
        env={"SINK": sink["name"]},
    )
    esm_uuid = _wire_event_source(ctx, fn["name"], table["stream_arn"], starting_position="TRIM_HORIZON")

    ddb = ctx.client("dynamodb")
    name = table["name"]
    # Three writes that each create an item, through three different operations.
    ddb.update_item(TableName=name, Key={"pk": {"S": "via-update"}},
                    UpdateExpression="SET qty = :q ADD hits :one",
                    ExpressionAttributeValues={":q": {"N": "5"}, ":one": {"N": "1"}})
    ddb.execute_statement(Statement=f"INSERT INTO \"{name}\" VALUE {{'pk': ?, 'note': ?}}",
                          Parameters=[{"S": "via-partiql"}, {"S": "hello"}])
    ddb.transact_write_items(TransactItems=[{"Put": {
        "TableName": name, "Item": {"pk": {"S": "via-transact"}, "tags": {"SS": ["b", "a"]}},
        "ConditionExpression": "attribute_not_exists(pk)",
    }}])
    # Then a write to an existing item, which is a MODIFY and not another INSERT.
    ddb.update_item(TableName=name, Key={"pk": {"S": "via-update"}},
                    UpdateExpression="ADD hits :one", ExpressionAttributeValues={":one": {"N": "1"}})

    inserted = {
        "via-update": {"pk": {"S": "via-update"}, "qty": {"N": "5"}, "hits": {"N": "1"}},
        "via-partiql": {"pk": {"S": "via-partiql"}, "note": {"S": "hello"}},
        "via-transact": {"pk": {"S": "via-transact"}, "tags": {"SS": ["a", "b"]}},
    }
    want = {
        f"{pk}#INSERT": {
            "event": "INSERT", "source_arn": table["stream_arn"], "view": "NEW_AND_OLD_IMAGES",
            "keys": _image({"pk": {"S": pk}}), "new_image": _image(img), "old_image": "-",
        }
        for pk, img in inserted.items()
    }
    want["via-update#MODIFY"] = {
        "event": "MODIFY", "source_arn": table["stream_arn"], "view": "NEW_AND_OLD_IMAGES",
        "keys": _image({"pk": {"S": "via-update"}}),
        "new_image": _image({**inserted["via-update"], "hits": {"N": "2"}}),
        "old_image": _image(inserted["via-update"]),
    }
    # The MODIFY follows the item's own INSERT in its shard, so its arrival shows every earlier
    # record for that key was read; the other two keys are awaited by count.
    got = _sink_items(ctx, sink["name"], len(want))
    assert got == want, f"expected exactly the three INSERT records and one MODIFY {want!r}, got {got!r}"
    # Tear down in reverse dependency order and prove each resource gone.
    _gone_esm(ctx, esm_uuid, table["stream_arn"])
    _gone_lambda(ctx, fn["name"])
    _gone_role(ctx, fn["role"], "/sim2real/")
    _gone_table(ctx, table["name"], {"pk": {"S": "gone"}})
    _gone_source_stream(ctx, table["stream_arn"])
    _gone_table(ctx, sink["name"], {"pk": {"S": "gone"}})

def _attr_json(value):
    """An attribute value as the stream event's JSON shows it: binary base64, sets sorted."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k == "B":
                out[k] = base64.b64encode(v).decode()
            elif k == "BS":
                out[k] = sorted(base64.b64encode(b).decode() for b in v)
            elif k in ("SS", "NS"):
                out[k] = sorted(v)
            else:
                out[k] = _attr_json(v)
        return out
    if isinstance(value, list):
        return [_attr_json(v) for v in value]
    return value


def _image(item) -> str:
    return json.dumps(_attr_json(item), sort_keys=True)


#: First delivery through a new mapping takes AWS longer than the other waits; a target that
#: needs more fails with the items it had written.
def _sink_items(ctx, sink_name, n, timeout_s=120):
    """Scan the sink until it holds at least n items (stream delivery is asynchronous)."""
    ddb = ctx.client("dynamodb")
    got = _wait_for_effect(
        lambda: _paged(ddb, "scan", "Items", TableName=sink_name, ConsistentRead=True),
        lambda items: len(items) >= n, timeout_s=timeout_s,
        description=f"{n} stream records written by the function",
    )
    return {i["pk"]["S"]: {k: v["S"] for k, v in i.items() if k != "pk"} for i in got}


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=40.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=40.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect (default 120s — Kinesis/DDB-stream ESMs can need
    60-120s for cold-start + first delivery; fast effects return as soon as the predicate holds).
    """
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _create_role(
    ctx, trust_service, inline_policy=None, managed_policies=None
) -> dict[str, str]:
    """Create an IAM role and register its (policy-detach-then-delete) teardown. Returns {name,arn}."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    # No blind sleep here: IAM role trust/permission propagation is absorbed by
    # _create_function_with_retry's bounded retry on "cannot be assumed", which is the
    # role's only consumer in this file.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion; DeleteConflict is
    retried while IAM catches up with the removals, and only an already-gone role (NoSuchEntity)
    is tolerated.
    """
    iam = ctx.client("iam")
    deadline = time.monotonic() + 40
    while True:
        try:
            for p in iam.list_attached_role_policies(RoleName=role_name).get(
                "AttachedPolicies", []
            ):
                iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
            for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchEntity":
                return
            if code != "DeleteConflict" or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _wait_function_active(ctx, name: str, timeout_s: float = 40) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} active",
    )


def _create_function_with_retry(
    ctx, handler_code, role_arn, env, timeout=30, memory=128, runtime="python3.12"
) -> dict[str, str]:
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active.
    Registers the function's teardown (LIFO-before its role, as the role was registered first).
    """
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    # Dedent the inline handler and alias `handler` to the fixed "lambda_function.lambda_handler"
    # entrypoint; without that symbol the function fails with Runtime.HandlerNotFound.
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs: dict[str, Any] = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(_tolerant(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
            # The function creates /aws/lambda/<name> on its first invoke and that log group
            # outlives the function, so it is deleted too.
            ctx.on_cleanup(
                _tolerant(
                    lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}"),
                    "ResourceNotFoundException",
                )
            )
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _create_lambda(
    ctx,
    handler_code,
    permissions=None,
    env=None,
    timeout=30,
    memory=128,
    runtime="python3.12",
) -> dict[str, str]:
    """Create a Lambda with an execution role scoped to `permissions` (a list of IAM statement
    fragments like [{"Action": ["sqs:SendMessage"], "Resource": queue_arn}]); logs are always
    allowed. Role + function each register their own teardown (function torn down first, LIFO).
    Returns {name,arn}.
    """
    # The partition comes from the caller identity, so the grant follows the target.
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": f"arn:{partition}:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = (
            perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        )
        resource = (
            perm["Resource"]
            if isinstance(perm["Resource"], list)
            else [perm["Resource"]]
        )
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resource})
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    fn = _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )
    return {**fn, "role": role["name"]}


def _create_table(
    ctx,
    key_schema=None,
    attributes=None,
    stream=False,
    stream_view_type="NEW_AND_OLD_IMAGES",
) -> dict[str, str]:
    """Create a DynamoDB table (PAY_PER_REQUEST; waits table_exists; registers delete_table).
    Returns {name,arn[,stream_arn]}.
    """
    name = _xname(ctx, "tbl")
    ddb = ctx.client("dynamodb")
    params: dict[str, Any] = {
        "TableName": name,
        "KeySchema": key_schema or [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": attributes
        or [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
        "Tags": _xsvc_tags_kv(),
    }
    if stream:
        params["StreamSpecification"] = {
            "StreamEnabled": True,
            "StreamViewType": stream_view_type,
        }
    resp = ddb.create_table(**params)
    ctx.on_cleanup(_tolerant(lambda: ddb.delete_table(TableName=name), "ResourceNotFoundException"))
    _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=40.0, interval_s=1.0, description=f"table {name} ACTIVE",
    )
    result = {"name": name, "arn": resp["TableDescription"]["TableArn"]}
    if stream:
        result["stream_arn"] = resp["TableDescription"].get("LatestStreamArn", "")
    return result


def _wire_event_source(
    ctx,
    function_name,
    source_arn,
    batch_size=10,
    starting_position=None,
    extra_config=None,
) -> str:
    """Create an event-source mapping (SQS/DynamoDB Streams/Kinesis/...) and wait until Enabled
    (registers delete_event_source_mapping teardown). Returns the ESM UUID.
    """
    lam = ctx.client("lambda")
    params: dict[str, Any] = {
        "FunctionName": function_name,
        "EventSourceArn": source_arn,
        "BatchSize": batch_size,
        "Enabled": True,
    }
    if starting_position:
        params["StartingPosition"] = starting_position
    elif any(
        s in source_arn
        for s in [":stream/", "/stream/", ":kinesis:", ":kafka:", ":documentdb:"]
    ):
        params["StartingPosition"] = "LATEST"
    if extra_config:
        params.update(extra_config)
    esm_uuid = lam.create_event_source_mapping(**params)["UUID"]
    ctx.on_cleanup(_tolerant(lambda: lam.delete_event_source_mapping(UUID=esm_uuid), "ResourceNotFoundException"))
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_uuid).get("State"),
        lambda s: s == "Enabled",
        timeout_s=40,
        interval_s=3.0,
        description=f"ESM {esm_uuid} Enabled",
    )
    return esm_uuid


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 40.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str) -> None:
    """``fn()`` must fail with one of ``codes`` in the HTTP class of ``status``, a non-empty message."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        in_class = isinstance(got, int) and got // 100 == status // 100
        assert code in codes and in_class, (
            f"{what}: expected {'/'.join(codes)} HTTP {status // 100}xx, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg.strip(), f"{what}: {code} carries an empty message"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer and grade that answer.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            last = fn()
        except ClientError as exc:
            code, got, msg = _err(exc)
            if code in codes:
                # Grade the refusal already received: a converging delete may still answer once more.
                assert isinstance(got, int) and got // 100 == status // 100, (
                    f"{what}: expected {code} HTTP {status // 100}xx, got HTTP {got!r}: {msg[:150]!r}"
                )
                assert msg.strip(), f"{what}: {code} carries an empty message"
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete; last answer {last!r:.300}")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


def _gone_esm(ctx, uuid: str, source_arn: str) -> None:
    lam = ctx.client("lambda")
    lam.delete_event_source_mapping(UUID=uuid)
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: lam.get_event_source_mapping(UUID=uuid), nf, 404, f"GetEventSourceMapping {uuid}")
    listed = {m["UUID"] for m in _paged(lam, "list_event_source_mappings", "EventSourceMappings", EventSourceArn=source_arn)}
    assert uuid not in listed, f"ListEventSourceMappings still lists deleted mapping {uuid}"
    _refused(lambda: lam.update_event_source_mapping(UUID=uuid, BatchSize=1), nf, 404, f"UpdateEventSourceMapping {uuid}")


def _gone_lambda(ctx, name: str) -> None:
    lam = ctx.client("lambda")
    lam.delete_function(FunctionName=name)
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: lam.get_function(FunctionName=name), nf, 404, f"GetFunction {name}")
    listed = {f["FunctionName"] for f in _paged(lam, "list_functions", "Functions")}
    assert name not in listed, f"ListFunctions still lists deleted function {name}"
    # Invoke keeps reaching a just-deleted function for a while on AWS, so it converges like GetFunction.
    _poll_refused(lambda: lam.invoke(FunctionName=name, Payload=b"{}"), nf, 404, f"Invoke {name}")


def _gone_role(ctx, name: str, path: str = "/") -> None:
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    nf = ("NoSuchEntity",)
    _poll_refused(lambda: iam.get_role(RoleName=name), nf, 404, f"GetRole {name}")
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix=path)}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}]}'
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        nf, 404, f"PutRolePolicy {name}",
    )


def _gone_table(ctx, name: str, item: dict) -> None:
    ddb = ctx.client("dynamodb")
    ddb.delete_table(TableName=name)
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: ddb.describe_table(TableName=name), nf, 400, f"DescribeTable {name}")
    assert name not in _paged(ddb, "list_tables", "TableNames"), f"ListTables still lists deleted table {name}"
    _refused(lambda: ddb.put_item(TableName=name, Item=item), nf, 400, f"PutItem {name}")


# ---- DynamoDB stream of a deleted table: DISABLED with every shard closed, or not found ----
def _gone_source_stream(ctx, stream_arn: str) -> None:
    """After DeleteTable, DescribeStream reports the stream DISABLED with every shard closed, or
    refuses it ResourceNotFoundException with AWS's exact message. AWS keeps a deleted table's
    stream readable for 24 hours, so its shards are not required to refuse a read."""
    streams = ctx.client("dynamodbstreams")
    deadline = time.monotonic() + _GONE_S
    while True:
        try:
            desc = streams.describe_stream(StreamArn=stream_arn)["StreamDescription"]
        except ClientError as exc:
            code, status, msg = _err(exc)
            assert (code, msg) == (
                "ResourceNotFoundException", f"Requested resource not found: Stream: {stream_arn} not found"
            ), f"DescribeStream on the deleted table's stream: got {code!r} HTTP {status!r}: {msg[:200]!r}"
            assert isinstance(status, int) and 400 <= status < 500, (
                f"DescribeStream ResourceNotFoundException: expected HTTP 4xx, got {status!r}"
            )
            return
        if desc["StreamStatus"] == "DISABLED":
            still_open = [s["ShardId"] for s in desc.get("Shards", [])
                          if not s.get("SequenceNumberRange", {}).get("EndingSequenceNumber")]
            assert not still_open, f"DISABLED stream still has open shards {still_open}"
            return
        assert desc["StreamStatus"] in ("ENABLED", "DISABLING"), (
            f"the deleted table's stream reached {desc['StreamStatus']!r}"
        )
        assert time.monotonic() < deadline, (
            f"stream still {desc['StreamStatus']} {_GONE_S:.0f}s after DeleteTable"
        )
        time.sleep(1.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
