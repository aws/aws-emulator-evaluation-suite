"""log-cwl-plumbing-lambda-filter-rejected-when-invoke-permission-names-another-group."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-cwl-plumbing-lambda-filter-rejected-when-invoke-permission-names-another-group"
GROUP = "subscription-delivery"
SERVICES = ["lambda", "logs"]

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
    "axis:rejection",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """An invoke permission scoped to log group A's SourceArn admits A's subscription filter and
    refuses B's with InvalidParameterException, so nothing written to B reaches the function while
    A's lines do; granting B's SourceArn then admits B's filter and B's line arrives."""
    logs = ctx.client("logs")
    lam = ctx.client("lambda")
    account = ctx.client("sts").get_caller_identity()["Account"]

    groups = []
    for tag in ("a", "b"):
        name = ctx.unique_name(f"sim2real-cwlp-src{tag}-lg-")
        logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK})
        ctx.on_cleanup(lambda n=name: logs.delete_log_group(logGroupName=n))
        logs.create_log_stream(logGroupName=name, logStreamName=f"{name}-s")
        groups.append(name)
    group_a, group_b = groups

    fn_name = ctx.unique_name("sim2real-cwlp-src-fn-")
    fn_arn, fn_log_group = _create_reporting_function(ctx, lam, logs, fn_name)
    _grant_logs_invoke(ctx, lam, fn_name, account, group_a)

    # Positive control first: the permission has propagated once A's filter is accepted.
    filter_a = ctx.unique_name("sim2real-cwlp-src-fa-")
    _put_lambda_filter(ctx, logs, group_a, filter_a, "", fn_arn)

    # --- 1. The identical filter on B is refused, with the exact code.
    filter_b = ctx.unique_name("sim2real-cwlp-src-fb-")
    try:
        logs.put_subscription_filter(
            logGroupName=group_b, filterName=filter_b, filterPattern="", destinationArn=fn_arn
        )
        raise AssertionError(
            f"expected PutSubscriptionFilter on {group_b} to be refused: the function's "
            f"invoke permission names only {group_a}"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a SourceArn-mismatched filter, got {code!r} "
        f"({message!r})"
    )
    expected_message = (
        "Could not execute the lambda function. Make sure you have given CloudWatch Logs "
        "permission to execute your function."
    )
    assert message == expected_message, (
        f"the SourceArn-mismatched filter was refused with message {message!r}, expected "
        f"{expected_message!r}"
    )
    filters_b = logs.describe_subscription_filters(logGroupName=group_b)["subscriptionFilters"]
    assert filters_b == [], f"the refused filter is attached to {group_b}: {filters_b!r}"

    # --- 2. Effect absent: B's line never reaches the function; A's lines do (barrier x2).
    marker = ctx.unique_name("cwlp-src-")
    line_b = f"{marker} from-b"
    line_a1, line_a2 = f"{marker} from-a-1", f"{marker} from-a-2"
    _put(logs, group_b, f"{group_b}-s", [{"timestamp": _now_ms(), "message": line_b}])
    _put(logs, group_a, f"{group_a}-s", [{"timestamp": _now_ms(), "message": line_a1}])
    _poll_until(
        lambda: _reports(logs, fn_log_group, group_a),
        lambda rs: line_a1 in _delivered(rs),
        timeout_s=240.0,
        interval_s=5.0,
        description=f"{line_a1!r} from the permitted group reaches {fn_name}",
    )
    _put(logs, group_a, f"{group_a}-s", [{"timestamp": _now_ms(), "message": line_a2}])
    _poll_until(
        lambda: _reports(logs, fn_log_group, group_a),
        lambda rs: line_a2 in _delivered(rs),
        timeout_s=240.0,
        interval_s=5.0,
        description=f"{line_a2!r} from the permitted group reaches {fn_name}",
    )
    from_b = _reports(logs, fn_log_group, group_b)
    assert from_b == [], f"the function was invoked for the refused group {group_b}: {from_b!r}"

    # --- 3. Repair the one broken thing: grant B's SourceArn; B's filter and line now work.
    _grant_logs_invoke(ctx, lam, fn_name, account, group_b)
    _put_lambda_filter(ctx, logs, group_b, filter_b, "", fn_arn)
    line_b2 = f"{marker} from-b-after-grant"

    def _put_b2_and_read():
        # A just-created filter may miss events ingested before it is active; rewrite each pass.
        _put(logs, group_b, f"{group_b}-s", [{"timestamp": _now_ms(), "message": line_b2}])
        return _reports(logs, fn_log_group, group_b)

    reports_b = _poll_until(
        _put_b2_and_read,
        lambda rs: line_b2 in _delivered(rs),
        timeout_s=240.0,
        interval_s=5.0,
        description=f"{line_b2!r} reaches {fn_name} once {group_b} is granted",
    )
    assert line_b not in _delivered(reports_b), (
        f"the line written to {group_b} while its filter was refused was delivered later: "
        f"{sorted(_delivered(reports_b))!r}"
    )
    for rep in reports_b:
        assert rep["env"]["subscriptionFilters"] == [filter_b], (
            f"expected B's envelopes to name {filter_b!r}, got {rep['env']['subscriptionFilters']!r}"
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
