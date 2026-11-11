"""obs-lambda-2-kinesis-esm-role-without-stream-read-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "obs-lambda-2-kinesis-esm-role-without-stream-read-rejected"
GROUP = "event-source-mapping"
SERVICES = ["cloudwatch", "kinesis", "lambda"]

_HANDLER = 'def lambda_handler(event, context):\n    return {"n": len(event["Records"])}\n'
_STREAM_READ = ["kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:DescribeStream",
                "kinesis:DescribeStreamSummary", "kinesis:ListShards", "kinesis:ListStreams"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """A Kinesis ESM whose role cannot read the stream is refused ("Cannot access stream") atomically;
    granting only the stream-read actions to the same role makes the same create succeed.
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    stream, stream_arn = _create_stream(ctx, ctx.unique_name("sim2real-xsvc-obs2neg-"))
    role_name, role_arn = _create_logs_only_role(ctx)
    fn = _create_function(ctx, ctx.unique_name("sim2real-xsvc-obs2neg-"), role_arn)

    got = _create_error(ctx, lam, fn, stream_arn)
    expected = (
        "InvalidParameterValueException",
        f"Cannot access stream {stream_arn}. Please ensure the role can perform the GetRecords, "
        f"GetShardIterator, DescribeStream, DescribeStreamSummary, ListShards, and ListStreams "
        f"Actions on your stream.",
    )
    assert got == expected, (
        f"mapping with a role that cannot read the stream returned {got!r}, expected {expected!r}"
    )
    assert _mappings(lam, fn) == [], f"rejected create left mapping(s) {_mappings(lam, fn)!r}"

    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": _STREAM_READ, "Resource": stream_arn}]}
    iam.put_role_policy(RoleName=role_name, PolicyName="stream-read",
                        PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="stream-read"))

    esm = _create_after_grant(ctx, lam, fn, stream_arn)
    assert esm.get("EventSourceArn") == stream_arn, f"control mapping source {esm!r}"
    assert _mappings(lam, fn) == [esm["UUID"]], (
        f"mappings after the grant are {_mappings(lam, fn)!r}, expected [{esm['UUID']!r}]"
    )
    _await_state(lam, esm["UUID"], "Disabled")


def _kwargs(fn: str, stream_arn: str) -> dict:
    return dict(FunctionName=fn, EventSourceArn=stream_arn, StartingPosition="TRIM_HORIZON",
                BatchSize=100, Enabled=False)


def _create_error(ctx: Any, lam: Any, fn: str, stream_arn: str) -> tuple[str, str]:
    from botocore.exceptions import ClientError
    try:
        resp = lam.create_event_source_mapping(**_kwargs(fn, stream_arn))
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=resp["UUID"]))
    raise AssertionError(
        f"mapping was ACCEPTED with a role that cannot read the stream; real AWS rejects it: {resp!r}"
    )


def _create_after_grant(ctx: Any, lam: Any, fn: str, stream_arn: str) -> dict:
    deadline = time.monotonic() + 150
    while True:
        try:
            esm = lam.create_event_source_mapping(**_kwargs(fn, stream_arn))
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            # IAM propagation: the grant is not effective yet, so the same refusal repeats.
            if "Cannot access stream" not in str(exc) or time.monotonic() > deadline:
                raise
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


def _create_logs_only_role(ctx: Any) -> tuple[str, str]:
    # Logs only - deliberately NO stream permissions, and no logs:CreateLogGroup (the check
    # owns the log group, see _own_log_group).
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
        "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/sim2real-xsvc-*:*"}]}
    iam.put_role_policy(RoleName=name, PolicyName="exec", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="exec"))
    return name, arn


def _create_stream(ctx: Any, name: str) -> tuple[str, str]:
    kin = ctx.client("kinesis")
    kin.create_stream(StreamName=name, ShardCount=1,
                      StreamModeDetails={"StreamMode": "PROVISIONED"})
    ctx.on_cleanup(lambda: kin.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    kin.get_waiter("stream_exists").wait(StreamName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    kin.add_tags_to_stream(StreamName=name, Tags={"sim2real": CHECK})
    arn = kin.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return name, arn


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
