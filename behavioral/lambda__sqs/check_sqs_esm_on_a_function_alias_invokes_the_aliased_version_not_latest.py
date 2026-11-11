"""sqs-esm-on-a-function-alias-invokes-the-aliased-version-not-latest."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-esm-on-a-function-alias-invokes-the-aliased-version-not-latest"

GROUP = "event-propagation"

SERVICES = ["lambda", "sqs"]

_ALIAS = "live"


def _relay_code(out_url: str, build: str) -> str:
    """Lambda code that relays which build, version and ARN handled each SQS record."""
    return f'''
import boto3, json
sqs = boto3.client("sqs")
def lambda_handler(event, context):
    for record in event["Records"]:
        sqs.send_message(QueueUrl="{out_url}", MessageBody=json.dumps({{
            "build": "{build}",
            "version": context.function_version,
            "invokedArn": context.invoked_function_arn,
            "body": record["body"],
        }}))
    return {{"ok": True}}
'''


def _wait_update_done(ctx, name: str) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name).get("LastUpdateStatus"),
        lambda s: s == "Successful",
        timeout_s=40.0,
        interval_s=2.0,
        description=f"Lambda {name} code update Successful",
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An SQS mapping on a function alias invokes the version it points to: with $LATEST updated past
    version 1, every relay of the message and of a later fence, through a quiet window, comes from
    version 1 via the alias ARN, never $LATEST, and the source queue drains.
    """
    queue = _create_queue(ctx)
    out = _create_queue(ctx)
    fn = _create_lambda(
        ctx,
        _relay_code(out["url"], "published"),
        permissions=[
            {
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": queue["arn"],
            },
            {"Action": ["sqs:SendMessage"], "Resource": out["arn"]},
        ],
    )
    lam = ctx.client("lambda")
    version = lam.publish_version(FunctionName=fn["name"])["Version"]
    assert version == "1", f"the first PublishVersion returned version {version!r}, expected '1'"
    lam.update_function_code(
        FunctionName=fn["name"], ZipFile=_zip(_relay_code(out["url"], "latest"))
    )
    _wait_update_done(ctx, fn["name"])
    alias_arn = lam.create_alias(FunctionName=fn["name"], Name=_ALIAS, FunctionVersion=version)[
        "AliasArn"
    ]
    assert alias_arn == f"{fn['arn']}:{_ALIAS}", (
        f"CreateAlias returned {alias_arn!r}, expected the function ARN + :{_ALIAS}"
    )

    esm_uuid = _wire_event_source(ctx, alias_arn, queue["arn"], batch_size=1)
    mapping = lam.get_event_source_mapping(UUID=esm_uuid)
    assert mapping["FunctionArn"] == alias_arn, (
        f"the mapping's FunctionArn is {mapping['FunctionArn']!r}, expected the alias ARN"
    )
    sqs = ctx.client("sqs")
    marker = ctx.unique_name("via-alias-")
    sqs.send_message(QueueUrl=queue["url"], MessageBody=marker)
    # Positive control sent after the marker: once its relay arrives, and for a quiet window after
    # it (delivery order is not guaranteed), every relay of either message is collected and graded.
    fence = ctx.unique_name("fence-")
    sqs.send_message(QueueUrl=queue["url"], MessageBody=fence)

    seen: list[dict] = []

    def probe():
        resp = sqs.receive_message(QueueUrl=out["url"], MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            seen.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=out["url"], ReceiptHandle=m["ReceiptHandle"])
        return list(seen)

    _poll_until(
        probe,
        lambda r: {marker, fence} <= {x["body"] for x in r},
        timeout_s=40.0,
        description="the marker and fence records relayed by the function",
    )
    quiet_until = time.monotonic() + _QUIET_S
    while time.monotonic() < quiet_until:
        probe()
    bodies = {x["body"] for x in seen}
    assert bodies == {marker, fence}, (
        f"the function relayed records {sorted(bodies)}, expected only the marker and fence"
    )
    got = {(x["build"], x["version"], x["invokedArn"]) for x in seen}
    # SQS and the mapping deliver at least once, so a redelivered copy is allowed; every copy must
    # come from the aliased version.
    assert got == {("published", "1", alias_arn)}, (
        f"records were handled as (build, version, invoked ARN) {sorted(got)!r}, "
        f"expected every delivery to be ('published', '1', <alias arn>)"
    )
    counts = ("ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible")
    _poll_until(
        lambda: sqs.get_queue_attributes(QueueUrl=queue["url"], AttributeNames=list(counts))[
            "Attributes"
        ],
        lambda a: all(a.get(k) == "0" for k in counts),
        timeout_s=40.0,
        description="source queue drained after consumption",
    )
    _gone_esm(ctx, esm_uuid, queue["arn"])
    _gone_lambda(ctx, fn["name"])
    _gone_role(ctx, fn["role"])
    _gone_queue(ctx, queue["name"], queue["url"])


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"

#: Bounded convergence for a delete to reach its terminal not-found answer; a deadline, never an
#: assertion on elapsed time.
_GONE_S = 40.0

#: How long relays are still collected after the fence arrives.
_QUIET_S = 10.0

_SQS_NF = "AWS.SimpleQueueService.NonExistentQueue"
_SQS_NF_MSG = "The specified queue does not exist."
_ESM_NF_MSG = "The resource you requested does not exist."


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=40.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _grade(exc: ClientError, code: str, status: int, what: str, message: str) -> None:
    got = _err(exc)
    assert got == (code, status, message), (
        f"{what}: expected {(code, status, message)!r}, got {(got[0], got[1], got[2][:200])!r}"
    )


def _refused(fn, code: str, status: int, what: str, message: str) -> None:
    """One call of ``fn`` must fail with exactly ``code``, ``status`` and ``message``."""
    try:
        fn()
    except ClientError as exc:
        _grade(exc, code, status, what, message)
        return
    raise AssertionError(f"{what}: expected {code} HTTP {status}, the call succeeded")


def _poll_refused(read, code: str, status: int, what: str, message: str) -> None:
    """Poll the read-only ``read`` until it answers ``code``, and grade that answer exactly.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + _GONE_S
    while True:
        try:
            last = read()
        except ClientError as exc:
            if _err(exc)[0] == code:
                _grade(exc, code, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what}: still readable {_GONE_S:.0f}s after the delete; last answer {last!r:.300}"
            )
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


def _create_role(ctx, inline_policy: dict) -> dict[str, str]:
    """Create a Lambda execution role with one inline policy; register its teardown."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role-lambda")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """Remove the inline policies, then the role; DeleteConflict is retried while IAM catches up,
    and only an already-gone role (NoSuchEntity) is tolerated."""
    iam = ctx.client("iam")
    deadline = time.monotonic() + 40.0
    while True:
        try:
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


def _zip(code: str) -> bytes:
    """A deployment package holding ``code`` as lambda_function.py."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(code))
    return buf.getvalue()


def _delete_function_log_group(ctx, name: str) -> None:
    """Delete /aws/lambda/<name>; a function that never ran has none to delete."""
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except logs.exceptions.ResourceNotFoundException:
        pass


def _create_lambda(ctx, handler_code: str, permissions: list[dict]) -> dict[str, str]:
    """Create a python3.12 function whose role allows logs plus ``permissions``; retry through the
    role-propagation window, wait until Active, and register the function and log-group teardown.
    Returns {name, arn, role}."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    statements += [{"Effect": "Allow", **p} for p in permissions]
    role = _create_role(ctx, {"Version": "2012-10-17", "Statement": statements})
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 30
    while True:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role["arn"],
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": _zip(handler_code)},
                Timeout=30,
                MemorySize=128,
                Tags=_xsvc_resource_tags(),
            )
            break
        except ClientError as exc:
            # A new role is briefly not assumable by Lambda.
            if _err(exc)[0] != "InvalidParameterValueException" or time.monotonic() >= deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(
        _tolerant(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException")
    )
    # The first invocation creates /aws/lambda/<name>, which outlives the function.
    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name).get("State"),
        lambda s: s == "Active",
        timeout_s=40.0,
        interval_s=2.0,
        description=f"Lambda {name} Active",
    )
    return {"name": name, "arn": resp["FunctionArn"], "role": role["name"]}


def _create_queue(ctx) -> dict[str, str]:
    """Create a standard SQS queue (registers its teardown). Returns {name,url,arn}."""
    name = _xname(ctx, "q")
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(_tolerant(lambda: sqs.delete_queue(QueueUrl=url), _SQS_NF))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"name": name, "url": url, "arn": arn}


def _gone_lambda(ctx, name: str) -> None:
    lam = ctx.client("lambda")
    lam.delete_function(FunctionName=name)
    nf = "ResourceNotFoundException"
    msg = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{name}"
    _poll_refused(lambda: lam.get_function(FunctionName=name), nf, 404, f"GetFunction {name}", msg)
    listed = {f["FunctionName"] for f in _paged(lam, "list_functions", "Functions")}
    assert name not in listed, f"ListFunctions still lists deleted function {name}"
    # Invoke keeps reaching a just-deleted function for a while, so it is polled; DryRun runs no
    # code. It resolves the unqualified name to $LATEST and names that in its message.
    _poll_refused(
        lambda: lam.invoke(FunctionName=name, InvocationType="DryRun"),
        nf,
        404,
        f"Invoke {name}",
        f"{msg}:$LATEST",
    )


def _gone_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    msg = f"The role with name {name} cannot be found."
    _poll_refused(lambda: iam.get_role(RoleName=name), "NoSuchEntity", 404, f"GetRole {name}", msg)
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix="/sim2real/")}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:GetQueueUrl", "Resource": "*"}],
        }
    )
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        "NoSuchEntity",
        404,
        f"PutRolePolicy {name}",
        msg,
    )


def _gone_queue(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    sqs.delete_queue(QueueUrl=url)
    # A deleted queue can keep answering for a while, so the read is polled.
    _poll_refused(
        lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}", _SQS_NF_MSG
    )
    listed = sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
    assert not [u for u in listed if u.rstrip("/").split("/")[-1] == name], (
        f"ListQueues still lists deleted queue {name}"
    )
    _refused(
        lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"),
        _SQS_NF,
        400,
        f"SendMessage {name}",
        _SQS_NF_MSG,
    )


def _wire_event_source(ctx, function_name: str, queue_arn: str, batch_size: int) -> str:
    """Create an SQS event source mapping, retrying while the role's grant propagates, and wait
    until Enabled (registers its teardown). Returns the mapping UUID."""
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 30
    while True:
        try:
            esm_uuid = lam.create_event_source_mapping(
                FunctionName=function_name,
                EventSourceArn=queue_arn,
                BatchSize=batch_size,
                Enabled=True,
            )["UUID"]
            break
        except ClientError as exc:
            if _err(exc)[0] != "InvalidParameterValueException" or time.monotonic() >= deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(
        _tolerant(
            lambda: lam.delete_event_source_mapping(UUID=esm_uuid), "ResourceNotFoundException"
        )
    )
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_uuid).get("State"),
        lambda s: s == "Enabled",
        timeout_s=40.0,
        interval_s=3.0,
        description=f"ESM {esm_uuid} Enabled",
    )
    return esm_uuid


def _gone_esm(ctx, uuid: str, source_arn: str) -> None:
    lam = ctx.client("lambda")
    lam.delete_event_source_mapping(UUID=uuid)
    nf = "ResourceNotFoundException"
    _poll_refused(
        lambda: lam.get_event_source_mapping(UUID=uuid),
        nf,
        404,
        f"GetEventSourceMapping {uuid}",
        _ESM_NF_MSG,
    )
    listed = {
        m["UUID"]
        for m in _paged(
            lam, "list_event_source_mappings", "EventSourceMappings", EventSourceArn=source_arn
        )
    }
    assert uuid not in listed, f"ListEventSourceMappings still lists deleted mapping {uuid}"
    _refused(
        lambda: lam.update_event_source_mapping(UUID=uuid, BatchSize=1),
        nf,
        404,
        f"UpdateEventSourceMapping {uuid}",
        _ESM_NF_MSG,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
