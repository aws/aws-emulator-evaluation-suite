"""events-rule-sqs-esm-lambda-pipeline."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-rule-sqs-esm-lambda-pipeline"

GROUP = "event-propagation"

SERVICES = ["dynamodb", "events", "lambda", "sqs"]

_HANDLER = """
import json, os, boto3

_ddb = boto3.client("dynamodb")


def handler(event, context):
    for record in event["Records"]:
        env = json.loads(record["body"])
        _ddb.put_item(TableName=os.environ["TABLE"], Item={
            "pk": {"S": env["detail"]["id"]},
            "source": {"S": env["source"]},
            "detailType": {"S": env["detail-type"]},
            "account": {"S": env["account"]},
            "region": {"S": env["region"]},
        })
    return {"ok": True}
"""


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A rule on a custom bus routes a matching event to SQS, an event-source mapping hands it
    to Lambda, and the function's DynamoDB write carries the envelope's source, type, account
    and region; then every resource is deleted and proven gone."""
    sqs = ctx.client("sqs")
    ddb = ctx.client("dynamodb")
    events = ctx.client("events")
    lam = ctx.client("lambda")

    table = _xname(ctx, "tbl")
    table_arn = ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_TAGS_KV,
    )["TableDescription"]["TableArn"]
    ctx.on_cleanup(_tolerant(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    queue = _xname(ctx, "q")
    queue_url = sqs.create_queue(QueueName=queue, tags=dict(_TAGS))["QueueUrl"]
    ctx.on_cleanup(_tolerant(lambda: sqs.delete_queue(QueueUrl=queue_url), *_SQS_NF))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    bus = _xname(ctx, "bus")
    events.create_event_bus(Name=bus, Tags=_TAGS_KV)
    ctx.on_cleanup(_tolerant(lambda: events.delete_event_bus(Name=bus), "ResourceNotFoundException"))
    source = ctx.unique_name("sim2real.pipeline.")
    rule = _xname(ctx, "rule")
    rule_arn = events.put_rule(
        Name=rule, EventBusName=bus, EventPattern=json.dumps({"source": [source]}), Tags=_TAGS_KV
    )["RuleArn"]
    ctx.on_cleanup(
        _tolerant(lambda: events.delete_rule(Name=rule, EventBusName=bus), "ResourceNotFoundException")
    )
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }],
    })})
    events.put_targets(Rule=rule, EventBusName=bus, Targets=[{"Id": "q", "Arn": queue_arn}])
    ctx.on_cleanup(
        _tolerant(
            lambda: events.remove_targets(Rule=rule, EventBusName=bus, Ids=["q"]),
            "ResourceNotFoundException",
        )
    )

    role = _create_role(ctx, [
        {"Effect": "Allow", "Resource": queue_arn,
         "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]},
        {"Effect": "Allow", "Resource": table_arn, "Action": ["dynamodb:PutItem"]},
    ])
    fn = _create_function(ctx, role["arn"], {"TABLE": table})
    esm = lam.create_event_source_mapping(
        EventSourceArn=queue_arn, FunctionName=fn, BatchSize=1, Enabled=True
    )["UUID"]
    ctx.on_cleanup(
        _tolerant(lambda: lam.delete_event_source_mapping(UUID=esm), "ResourceNotFoundException")
    )
    _wait_esm_enabled(lam, esm)

    marker = ctx.unique_name("evt-")
    detail_type = "sim2real.pipeline.test"
    item = _reemit_until_written(ctx, bus, source, detail_type, marker, table)
    for field, want in (
        ("source", source),
        ("detailType", detail_type),
        ("account", ctx.account),
        ("region", ctx.region),
    ):
        got = item.get(field, {}).get("S")
        assert got == want, f"the function recorded {field}={got!r}, expected {want!r}"
    _wait_queue_drained(sqs, queue_url)

    # Tear down in reverse dependency order and prove each resource gone.
    _gone_esm(ctx, esm, queue_arn)
    _gone_lambda(ctx, fn)
    _gone_role(ctx, role["name"], _ROLE_PATH)
    _gone_rule(ctx, rule, ["q"], bus)
    _gone_event_bus(ctx, bus)
    _gone_queue(ctx, queue, queue_url)
    _gone_table(ctx, table, {"pk": {"S": marker}})


_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true"}
_TAGS_KV = [{"Key": k, "Value": v} for k, v in _TAGS.items()]
_ROLE_PATH = "/sim2real/"
_ROLE_PROPAGATION_S = 90.0
_DELIVERY_S = 120.0


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _create_role(ctx, statements: list) -> dict:
    iam = ctx.client("iam")
    name = _xname(ctx, "role")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(
        RoleName=name, Path=_ROLE_PATH, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS_KV
    )["Role"]["Arn"]
    ctx.on_cleanup(_tolerant(lambda: _delete_role(iam, name), "NoSuchEntity"))
    statements = statements + [{"Effect": "Allow", "Resource": "*", "Action": [
        "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]}]
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    return {"name": name, "arn": arn}


def _delete_role(iam, name: str) -> None:
    for pname in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=name, PolicyName=pname)
    iam.delete_role(RoleName=name)


def _create_function(ctx, role_arn: str, env: dict) -> str:
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    name = _xname(ctx, "fn")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _HANDLER)
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        try:
            lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": buf.getvalue()}, Timeout=30, MemorySize=128,
                Environment={"Variables": env}, Tags=dict(_TAGS),
            )
            break
        except ClientError as exc:
            # A just-created role is not yet assumable by Lambda.
            if _err(exc)[0] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(
        _tolerant(lambda: logs.delete_log_group(logGroupName=f"/aws/lambda/{name}"),
                  "ResourceNotFoundException")
    )
    ctx.on_cleanup(_tolerant(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        state = lam.get_function_configuration(FunctionName=name).get("State")
        if state == "Active":
            return name
        assert state != "Failed", f"function {name} reached State Failed"
        assert time.monotonic() < deadline, f"function {name} still {state!r}"
        time.sleep(2)


def _wait_esm_enabled(lam, uuid: str) -> None:
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        state = lam.get_event_source_mapping(UUID=uuid)["State"]
        if state == "Enabled":
            return
        assert state in ("Creating", "Enabling", "Updating"), f"mapping {uuid} reached {state!r}"
        assert time.monotonic() < deadline, f"mapping {uuid} still {state!r}"
        time.sleep(2)


def _reemit_until_written(ctx, bus, source, detail_type, marker, table) -> dict:
    """PutEvents until the function's write for ``marker`` is readable; EventBridge never retries
    an event a just-created rule dropped, so re-emitting is the bounded convergence."""
    events = ctx.client("events")
    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + _DELIVERY_S
    while True:
        resp = events.put_events(Entries=[{
            "EventBusName": bus, "Source": source, "DetailType": detail_type,
            "Detail": json.dumps({"id": marker}),
        }])
        assert resp.get("FailedEntryCount") == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"
        poll_until = min(deadline, time.monotonic() + 10)
        while time.monotonic() < poll_until:
            item = ddb.get_item(TableName=table, Key={"pk": {"S": marker}}, ConsistentRead=True)
            if "Item" in item:
                return item["Item"]
            time.sleep(1)
        assert time.monotonic() < deadline, (
            f"no DynamoDB write for event {marker} within {_DELIVERY_S:.0f}s of re-emitting"
        )


def _wait_queue_drained(sqs, url: str) -> None:
    """The mapping deleted what the function consumed: nothing visible and nothing in flight."""
    keys = ["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"]
    deadline = time.monotonic() + _DELIVERY_S
    while True:
        attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=keys)["Attributes"]
        if all(attrs.get(k) == "0" for k in keys):
            return
        assert time.monotonic() < deadline, f"the queue never drained: {attrs!r}"
        time.sleep(2)


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status``, exactly the message ``message``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message: expected {message!r}, got {msg!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
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


_SQS_NF = ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")
_SQS_GONE = "The specified queue does not exist."
_ESM_GONE = "The resource you requested does not exist."


def _gone_esm(ctx, uuid: str, source_arn: str) -> None:
    lam = ctx.client("lambda")
    lam.delete_event_source_mapping(UUID=uuid)
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: lam.get_event_source_mapping(UUID=uuid), nf, 404, f"GetEventSourceMapping {uuid}", _ESM_GONE)
    listed = {m["UUID"] for m in _paged(lam, "list_event_source_mappings", "EventSourceMappings", EventSourceArn=source_arn)}
    assert uuid not in listed, f"ListEventSourceMappings still lists deleted mapping {uuid}"
    _refused(lambda: lam.update_event_source_mapping(UUID=uuid, BatchSize=1), nf, 404, f"UpdateEventSourceMapping {uuid}", _ESM_GONE)


def _gone_lambda(ctx, name: str) -> None:
    lam = ctx.client("lambda")
    lam.delete_function(FunctionName=name)
    nf = ("ResourceNotFoundException",)
    gone = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{name}"
    _poll_refused(lambda: lam.get_function(FunctionName=name), nf, 404, f"GetFunction {name}", gone)
    listed = {f["FunctionName"] for f in _paged(lam, "list_functions", "Functions")}
    assert name not in listed, f"ListFunctions still lists deleted function {name}"
    _poll_refused(lambda: lam.invoke(FunctionName=name, Payload=b"{}"), nf, 404, f"Invoke {name}", f"{gone}:$LATEST")


def _gone_role(ctx, name: str, path: str = "/") -> None:
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    nf = ("NoSuchEntity",)
    gone = f"The role with name {name} cannot be found."
    _poll_refused(lambda: iam.get_role(RoleName=name), nf, 404, f"GetRole {name}", gone)
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix=path)}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}]}'
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        nf, 404, f"PutRolePolicy {name}", gone,
    )


def _gone_rule(ctx, name: str, target_ids: list[str], bus: str = "default") -> None:
    ev = ctx.client("events")
    if target_ids:
        ev.remove_targets(Rule=name, EventBusName=bus, Ids=target_ids)
    ev.delete_rule(Name=name, EventBusName=bus)
    nf = ("ResourceNotFoundException",)
    gone = f"Rule {name} does not exist on EventBus {bus}."
    _poll_refused(lambda: ev.describe_rule(Name=name, EventBusName=bus), nf, 400, f"DescribeRule {name}", gone)
    listed = {r["Name"] for r in ev.list_rules(NamePrefix=name, EventBusName=bus).get("Rules", [])}
    assert name not in listed, f"ListRules still lists deleted rule {name}"
    _refused(
        lambda: ev.put_targets(Rule=name, EventBusName=bus, Targets=[{"Id": "gone", "Arn": f"arn:aws:sqs:{ctx.region}:{ctx.account}:gone"}]),
        nf, 400, f"PutTargets {name}", gone,
    )


def _gone_event_bus(ctx, name: str) -> None:
    ev = ctx.client("events")
    ev.delete_event_bus(Name=name)
    nf = ("ResourceNotFoundException",)
    gone = f"Event bus {name} does not exist."
    _poll_refused(lambda: ev.describe_event_bus(Name=name), nf, 400, f"DescribeEventBus {name}", gone)
    listed = {b["Name"] for b in ev.list_event_buses(NamePrefix=name).get("EventBuses", [])}
    assert name not in listed, f"ListEventBuses still lists deleted bus {name}"
    # The dead bus is unusable: PutRule naming it is refused.
    _refused(
        lambda: ev.put_rule(Name="sim2real-gone", EventBusName=name,
                            EventPattern=json.dumps({"source": ["gone"]})),
        nf, 400, f"PutRule on deleted bus {name}", gone,
    )
    # Extra: AWS accepts PutEvents naming a bus that does not exist: a 200 with no failed entry and an
    # EventId, the event routed nowhere (the bus stays absent, re-checked below).
    entries = [{"EventBusName": name, "Source": "gone", "DetailType": "gone", "Detail": "{}"}]
    resp = ev.put_events(Entries=entries)
    entry = resp["Entries"][0]
    assert resp.get("FailedEntryCount", 0) == 0 and entry.get("EventId"), (
        f"PutEvents to deleted bus {name}: expected the silent accept (no failed entry, an EventId), got {resp!r}"
    )
    _refused(lambda: ev.describe_event_bus(Name=name), nf, 400, f"DescribeEventBus {name} after PutEvents", gone)


def _gone_queue(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    sqs.delete_queue(QueueUrl=url)
    # AWS documents up to 60 s for a deleted queue to stop answering.
    _poll_refused(lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}", _SQS_GONE)
    listed = sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
    assert not [u for u in listed if u.rstrip("/").split("/")[-1] == name], (
        f"ListQueues still lists deleted queue {name}"
    )
    _refused(lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"), _SQS_NF, 400, f"SendMessage {name}", _SQS_GONE)


def _gone_table(ctx, name: str, item: dict) -> None:
    ddb = ctx.client("dynamodb")
    ddb.delete_table(TableName=name)
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: ddb.describe_table(TableName=name), nf, 400, f"DescribeTable {name}",
                  f"Requested resource not found: Table: {name} not found")
    assert name not in _paged(ddb, "list_tables", "TableNames"), f"ListTables still lists deleted table {name}"
    _refused(lambda: ddb.put_item(TableName=name, Item=item), nf, 400, f"PutItem {name}", "Requested resource not found")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
