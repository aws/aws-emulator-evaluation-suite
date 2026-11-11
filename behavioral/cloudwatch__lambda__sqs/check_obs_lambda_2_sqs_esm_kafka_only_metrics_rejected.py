"""obs-lambda-2-sqs-esm-kafka-only-metrics-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "obs-lambda-2-sqs-esm-kafka-only-metrics-rejected"
GROUP = "event-source-mapping"
SERVICES = ["cloudwatch", "lambda", "sqs"]

_HANDLER = 'def lambda_handler(event, context):\n    return {"n": len(event["Records"])}\n'
_BAD = ((["KafkaMetrics"], "Invalid EventSourceMapping metrics. Expected values: [EventCount]"),
        (["ErrorCount"], "Invalid EventSourceMapping metrics. Expected values: [EventCount]"),
        (["EventCount", "EventCount"], "MetricsConfig contains duplicate metrics."))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """An SQS event source mapping with MetricsConfig KafkaMetrics, ErrorCount or a duplicated
    EventCount fails with the exact InvalidParameterValueException and creates nothing; EventCount
    alone is accepted and the mapping consumes."""
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")

    role_arn = _create_role(ctx)
    url, arn = _create_queue(ctx, ctx.unique_name("sim2real-xsvc-obs2neg-"))
    fn = _create_function(ctx, ctx.unique_name("sim2real-xsvc-obs2neg-"), role_arn)

    refusals, expected = [], []
    for bad, message in _BAD:
        refusals.append((bad, _create_error(ctx, lam, fn, arn, bad)))
        expected.append((bad, ("InvalidParameterValueException", message)))
        left = _mappings(lam, fn)
        assert left == [], f"rejected MetricsConfig {bad!r} still created mapping(s) {left!r}"
    assert refusals == expected, (
        f"MetricsConfig refusals on an SQS mapping were {refusals!r}, expected {expected!r}"
    )

    esm = _create_ok(ctx, lam, fn, arn)
    assert esm.get("MetricsConfig") == {"Metrics": ["EventCount"]}, (
        f"positive control: EventCount create returned MetricsConfig {esm.get('MetricsConfig')!r}"
    )
    assert _mappings(lam, fn) == [esm["UUID"]], (
        f"positive control: mappings for {fn} are {_mappings(lam, fn)!r}, expected [{esm['UUID']!r}]"
    )
    _await_state(lam, esm["UUID"], "Enabled")
    sqs.send_message(QueueUrl=url, MessageBody=json.dumps({"kind": "control"}))
    depth = _poll(lambda: _depth(sqs, url), lambda d: d == (0, 0), 180, "control message consumed")
    assert depth == (0, 0), f"positive-control mapping did not consume the message: {depth!r}"


def _create_error(ctx: Any, lam: Any, fn: str, arn: str, metrics: list) -> tuple[str, str]:
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + 120
    while True:
        try:
            resp = lam.create_event_source_mapping(FunctionName=fn, EventSourceArn=arn,
                                                   MetricsConfig={"Metrics": metrics})
            break
        except ClientError as exc:
            code, msg = exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
            # IAM propagation answers with the same code but a permissions message; that is
            # not the rejection under test, so wait it out (bounded) and ask again.
            if "does not have permissions" in msg and time.monotonic() < deadline:
                print(f"[retry] create_event_source_mapping: {msg}")
                time.sleep(5)
                continue
            return code, msg
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=resp["UUID"]))
    raise AssertionError(
        f"MetricsConfig {metrics!r} was ACCEPTED on an SQS mapping, real AWS rejects it: {resp!r}"
    )


def _create_ok(ctx: Any, lam: Any, fn: str, arn: str) -> dict:
    deadline = time.monotonic() + 120
    while True:
        try:
            esm = lam.create_event_source_mapping(FunctionName=fn, EventSourceArn=arn,
                                                  MetricsConfig={"Metrics": ["EventCount"]})
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            # IAM propagation: the role's queue permissions are not effective yet.
            if "Expected values" in str(exc) or time.monotonic() > deadline:
                raise
            print(f"[retry] create_event_source_mapping: {exc}")
            time.sleep(5)
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=esm["UUID"]))
    return esm


def _mappings(lam: Any, fn: str) -> list:
    out, marker = [], None
    while True:
        kw = {"FunctionName": fn, **({"Marker": marker} if marker else {})}
        page = lam.list_event_source_mappings(**kw)
        out += [m["UUID"] for m in page.get("EventSourceMappings", [])]
        marker = page.get("NextMarker")
        if not marker:
            return out


def _poll(probe, pred, timeout_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(5)
    raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")


def _depth(sqs: Any, url: str) -> tuple[int, int]:
    a = sqs.get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return int(a["ApproximateNumberOfMessages"]), int(a["ApproximateNumberOfMessagesNotVisible"])


def _create_role(ctx: Any) -> str:
    # Inline policy, deliberately WITHOUT logs:CreateLogGroup: the check owns the log group
    # (see _own_log_group), so a log flush buffered past delete_function cannot recreate it.
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-obs2role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/sim2real-xsvc-*:*"}, {
        "Effect": "Allow",
        "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
        "Resource": "*"}]}
    iam.put_role_policy(RoleName=name, PolicyName="exec", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="exec"))
    return arn


def _create_queue(ctx: Any, name: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, Attributes={"VisibilityTimeout": "60"},
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _own_log_group(ctx: Any, fn_name: str) -> None:
    # Created BEFORE the function, and the role cannot create one. LIFO cleanup deletes it
    # after delete_function, so a late buffered flush gets AccessDenied instead of
    # resurrecting the group; the reap still loops in case one lands mid-delete.
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})

    def _reap() -> None:
        for _ in range(6):
            try:
                logs.delete_log_group(logGroupName=group)
            except logs.exceptions.ResourceNotFoundException:
                pass
            time.sleep(5)
            found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
            if not any(g["logGroupName"] == group for g in found):
                return
        raise RuntimeError(f"log group {group} kept reappearing")

    ctx.on_cleanup(_reap)


def _create_function(ctx: Any, name: str, role_arn: str) -> str:
    lam = ctx.client("lambda")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", _HANDLER)
    _own_log_group(ctx, name)
    deadline = time.monotonic() + 120
    while True:
        try:
            lam.create_function(FunctionName=name, Runtime="python3.12", Role=role_arn,
                                Handler="lambda_function.lambda_handler",
                                Code={"ZipFile": buf.getvalue()}, Timeout=30,
                                Tags={"sim2real": CHECK})
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            # IAM propagation: the new role is not yet assumable by Lambda.
            if "cannot be assumed" not in str(exc) or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name


def _await_state(lam: Any, uuid: str, want: str) -> None:
    deadline = time.monotonic() + 120
    state = None
    while time.monotonic() < deadline:
        state = lam.get_event_source_mapping(UUID=uuid)["State"]
        if state == want:
            return
        time.sleep(3)
    raise AssertionError(f"event source mapping {uuid} stuck in {state!r}, wanted {want!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
