"""log-cwl-plumbing-lambda-envelope-carries-only-pattern-matched-lines."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "log-cwl-plumbing-lambda-envelope-carries-only-pattern-matched-lines"
GROUP = "subscription-delivery"
SERVICES = ["lambda", "logs"]

_MATCH = "SIM2REALHIT"
_ENVELOPE_TAG = "SIM2REAL-ENVELOPE "

# The handler reports what it was actually handed: the raw event keys, the first two bytes
# of the base64-decoded payload, and the decompressed envelope. The check reads that report
# back from the function's own log group.
_HANDLER = r'''
import base64, gzip, json

def handler(event, context):
    raw = base64.b64decode(event["awslogs"]["data"])
    env = json.loads(gzip.decompress(raw))
    print("SIM2REAL-ENVELOPE " + json.dumps({
        "event_keys": sorted(event.keys()),
        "awslogs_keys": sorted(event["awslogs"].keys()),
        "magic": raw[:2].hex(),
        "env": env,
    }))
'''


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A subscription filter with a pattern delivers to Lambda (base64+gzip in event.awslogs.data)
    exactly the matching lines with their messages, timestamps and FilterLogEvents ids, while the
    non-matching line from the same batch is not delivered yet is still stored in the group."""
    logs = ctx.client("logs")
    lam = ctx.client("lambda")
    account = ctx.client("sts").get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-cwlp-lam-lg-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    log_stream = f"{group}-s"
    logs.create_log_stream(logGroupName=group, logStreamName=log_stream)

    fn_name = ctx.unique_name("sim2real-cwlp-lam-fn-")
    fn_arn, fn_log_group = _create_reporting_function(ctx, lam, logs, fn_name)
    _grant_logs_invoke(ctx, lam, fn_name, account, group)

    filter_name = ctx.unique_name("sim2real-cwlp-lam-f-")
    _put_lambda_filter(ctx, logs, group, filter_name, _MATCH, fn_arn)

    marker = ctx.unique_name("cwlp-lam-")
    hits = [f"{_MATCH} {marker} alpha", f"{_MATCH} {marker} beta"]
    noise = f"quiet {marker} gamma"
    base = _now_ms() - 2_000
    batch = [
        {"timestamp": base, "message": hits[0]},
        {"timestamp": base + 5, "message": noise},
        {"timestamp": base + 10, "message": hits[1]},
    ]
    expected_ts = {e["message"]: e["timestamp"] for e in batch}
    _put(logs, group, log_stream, batch)

    reports = _poll_until(
        lambda: _reports(logs, fn_log_group, group),
        lambda rs: set(hits) <= _delivered(rs),
        timeout_s=240.0,
        interval_s=5.0,
        description=f"both matching lines reach {fn_name} through the subscription filter",
    )

    source_ids = _source_event_ids(logs, group, [*hits, noise])
    delivered_ids: dict[str, set[str]] = {}
    for rep in reports:
        assert rep["event_keys"] == ["awslogs"] and rep["awslogs_keys"] == ["data"], (
            f"expected the Lambda event to be exactly {{'awslogs': {{'data': ...}}}}, got keys "
            f"{rep['event_keys']!r} / {rep['awslogs_keys']!r}"
        )
        assert rep["magic"] == "1f8b", (
            f"expected the base64-decoded awslogs.data to be gzip (1f8b), got {rep['magic']!r}"
        )
        env = rep["env"]
        assert env["messageType"] == "DATA_MESSAGE", f"messageType was {env['messageType']!r}"
        assert env["owner"] == account, f"expected owner {account!r}, got {env['owner']!r}"
        assert env["logStream"] == log_stream, (
            f"expected logStream {log_stream!r}, got {env['logStream']!r}"
        )
        assert env["subscriptionFilters"] == [filter_name], (
            f"expected subscriptionFilters [{filter_name!r}], got {env['subscriptionFilters']!r}"
        )
        for ev in env["logEvents"]:
            assert ev["message"] in hits, (
                f"the Lambda was handed a line the pattern {_MATCH!r} does not match: "
                f"{ev['message']!r}"
            )
            assert ev["timestamp"] == expected_ts[ev["message"]], (
                f"expected timestamp {expected_ts[ev['message']]} for {ev['message']!r}, got "
                f"{ev['timestamp']!r}"
            )
            delivered_ids.setdefault(ev["message"], set()).add(ev["id"])
    for hit in hits:
        assert delivered_ids[hit] == {source_ids[hit]}, (
            f"expected delivered id for {hit!r} to equal source eventId {source_ids[hit]!r}, "
            f"got {delivered_ids[hit]!r}"
        )

    # Differential barrier: a later matching line must arrive too; the noise line, written
    # in the earlier batch, still must not.
    later = f"{_MATCH} {marker} delta"
    _put(logs, group, log_stream, [{"timestamp": _now_ms(), "message": later}])
    reports = _poll_until(
        lambda: _reports(logs, fn_log_group, group),
        lambda rs: later in _delivered(rs),
        timeout_s=240.0,
        interval_s=5.0,
        description=f"the later matching line {later!r} reaches {fn_name}",
    )
    assert noise not in _delivered(reports), (
        f"the non-matching line {noise!r} was delivered: {sorted(_delivered(reports))!r}"
    )

    stored = _poll_until(
        lambda: _stored(logs, group, log_stream),
        lambda msgs: set(msgs) == {*hits, noise, later},
        timeout_s=120.0,
        interval_s=3.0,
        description=f"the group {group} still holds every line, matching or not",
    )
    assert stored.count(noise) == 1, (
        f"expected the filtered-out line to remain stored exactly once, got {stored!r}"
    )


# ===== helpers =====
def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate() holds; RAISE on the deadline (never return last)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _put(logs, group: str, stream: str, events: list[dict]) -> None:
    resp = logs.put_log_events(logGroupName=group, logStreamName=stream, logEvents=events)
    assert not resp.get("rejectedLogEventsInfo"), (
        f"expected every event accepted, got {resp.get('rejectedLogEventsInfo')!r}"
    )


def _stored(logs, group: str, stream: str) -> list[str]:
    out: list[str] = []
    kwargs = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
    while True:
        page = logs.get_log_events(**kwargs)
        out.extend(e["message"] for e in page["events"])
        if not page["events"] or page.get("nextForwardToken") == kwargs.get("nextToken"):
            return out
        kwargs["nextToken"] = page["nextForwardToken"]


def _source_event_ids(logs, group: str, lines: list[str]) -> dict[str, str]:
    def _read():
        out: dict[str, str] = {}
        kwargs = {"logGroupName": group}
        while True:
            page = logs.filter_log_events(**kwargs)
            for e in page.get("events", []):
                out[e["message"]] = e["eventId"]
            if not page.get("nextToken"):
                return out
            kwargs["nextToken"] = page["nextToken"]

    return _poll_until(
        _read,
        lambda ids: set(lines) <= set(ids),
        timeout_s=120.0,
        interval_s=3.0,
        description=f"FilterLogEvents reports an eventId for every line in {group}",
    )


def _reports(logs, fn_log_group: str, source_group: str) -> list[dict]:
    """Every envelope report the function printed that concerns ``source_group``."""
    out: list[dict] = []
    kwargs = {"logGroupName": fn_log_group, "filterPattern": '"SIM2REAL-ENVELOPE"'}
    while True:
        try:
            page = logs.filter_log_events(**kwargs)
        except logs.exceptions.ResourceNotFoundException:
            return out
        for e in page.get("events", []):
            msg = e["message"]
            if msg.startswith(_ENVELOPE_TAG):
                rep = json.loads(msg[len(_ENVELOPE_TAG):])
                if rep["env"].get("logGroup") == source_group:
                    out.append(rep)
        if not page.get("nextToken"):
            return out
        kwargs["nextToken"] = page["nextToken"]


def _delivered(reports: list[dict]) -> set[str]:
    return {e["message"] for r in reports for e in r["env"]["logEvents"]}


def _reap_log_group_loop(logs, name: str) -> None:
    """delete_function does not remove /aws/lambda/<fn>, and a buffered flush can recreate it
    after the delete: re-delete, then watch for reappearance over a bounded window."""
    for _ in range(6):
        try:
            logs.delete_log_group(logGroupName=name)
        except logs.exceptions.ResourceNotFoundException:
            pass
        time.sleep(5)
        found = logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])
        if not any(g["logGroupName"] == name for g in found):
            return
    raise RuntimeError(f"log group {name} kept reappearing after delete_function")


def _create_reporting_function(ctx, lam, logs, fn_name: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    region = ctx.region
    account = ctx.client("sts").get_caller_identity()["Account"]
    fn_log_group = f"/aws/lambda/{fn_name}"

    # Registered BEFORE the function exists, so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group_loop(logs, fn_log_group))
    logs.create_log_group(logGroupName=fn_log_group, tags={"sim2real": CHECK})
    logs.put_retention_policy(logGroupName=fn_log_group, retentionInDays=1)

    role_name = ctx.unique_name("sim2real-cwlp-lam-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _drop_role() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="write-own-logs")
        finally:
            iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_drop_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="write-own-logs",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": f"arn:aws:logs:{region}:{account}:log-group:{fn_log_group}:*",
                    }
                ],
            }
        ),
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _HANDLER)
    code = buf.getvalue()

    def _create():
        try:
            return lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=30,
                Tags={"sim2real": CHECK},
            )["FunctionArn"]
        except lam.exceptions.InvalidParameterValueException as exc:
            # The one IAM-propagation signal: "The role defined for the function cannot be
            # assumed by Lambda."
            if "cannot be assumed" in str(exc):
                return None
            raise

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    fn_arn = _poll_until(
        _create,
        lambda arn: arn is not None,
        timeout_s=120.0,
        interval_s=2.0,
        description=f"create_function {fn_name} once its role is assumable",
    )
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_arn, fn_log_group


def _grant_logs_invoke(ctx, lam, fn_name: str, account: str, group: str) -> None:
    lam.add_permission(
        FunctionName=fn_name,
        StatementId=ctx.unique_name("cwl-invoke-"),
        Action="lambda:InvokeFunction",
        Principal="logs.amazonaws.com",
        SourceArn=f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}:*",
        SourceAccount=account,
    )


def _put_lambda_filter(ctx, logs, group, filter_name, pattern, fn_arn) -> None:
    """Retry only while the resource policy has not propagated (InvalidParameterException)."""

    def _attempt():
        try:
            logs.put_subscription_filter(
                logGroupName=group,
                filterName=filter_name,
                filterPattern=pattern,
                destinationArn=fn_arn,
            )
        except logs.exceptions.InvalidParameterException as exc:
            return str(exc)
        return True

    ctx.on_cleanup(
        lambda: logs.delete_subscription_filter(logGroupName=group, filterName=filter_name)
    )
    _poll_until(
        _attempt,
        lambda r: r is True,
        timeout_s=120.0,
        interval_s=5.0,
        description=f"PutSubscriptionFilter to {fn_arn} accepted on {group}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
