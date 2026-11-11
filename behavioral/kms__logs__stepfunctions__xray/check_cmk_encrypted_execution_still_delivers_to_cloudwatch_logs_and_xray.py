"""cmk-encrypted-execution-still-delivers-to-cloudwatch-logs-and-xray."""
from __future__ import annotations

import json
import os
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cmk-encrypted-execution-still-delivers-to-cloudwatch-logs-and-xray"
GROUP = "cmk_encryption"
SERVICES = ["kms", "logs", "stepfunctions", "xray"]

_ROOT_RE = re.compile(r"Root=(1-[0-9a-f]{8}-[0-9a-f]{24})")
_VALIDATION_STREAM = "log_stream_created_by_aws_to_validate_log_delivery_subscriptions"
_LOG_BUDGET_S = 240.0
_XRAY_BUDGET_S = 420.0
_POLL_S = 2.0


@tags("axis:happy-path", "dp:api", "plane:data", "cap:c3", "concern:e2e")
def run(ctx) -> None:
    """A CUSTOMER_MANAGED_KMS_KEY-encrypted Express state machine whose key policy grants
    delivery.logs.amazonaws.com kms:Decrypt still succeeds, logs its decrypted input and
    history to CloudWatch Logs and publishes its execution's trace to X-Ray.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/encryption-at-rest.html
    """
    kms = ctx.client("kms")
    sfn = ctx.client("stepfunctions")
    xray = ctx.client("xray")
    account = ctx.client("sts").get_caller_identity()["Account"]

    key = _key(ctx, kms, account)
    role_arn = _role(ctx, key["Arn"])
    group, group_arn = _log_group(ctx, account)
    sm_arn = _state_machine(ctx, sfn, role_arn, key["Arn"], group_arn)

    enc = sfn.describe_state_machine(stateMachineArn=sm_arn).get("encryptionConfiguration")
    assert enc == {"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key["Arn"],
                   "kmsDataKeyReusePeriodSeconds": 60}, (
        f"DescribeStateMachine must report the CMK configuration it was created with; got {enc!r}")

    resp, own_root, own_marker, own = _warm_up_until_logged(ctx, sfn, sm_arn, group)
    assert resp["status"] == "SUCCEEDED", (
        f"a CMK-encrypted, logged and traced execution must SUCCEED; got {resp['status']!r} "
        f"error={resp.get('error')!r} cause={resp.get('cause')!r}"
    )
    out = json.loads(resp["output"])
    assert out == {"account": account}, (
        f"the execution's decrypted output must be the Task's own result; got {out!r}"
    )
    logged_input = json.loads(own[0]["details"]["input"])
    assert logged_input["marker"] == own_marker, (
        f"the logged ExecutionStarted must carry this execution's own (decrypted) input; "
        f"got {own[0]!r}")
    assert own[-1]["type"] == "ExecutionSucceeded", (
        f"the logged history must end ExecutionSucceeded; got {[e['type'] for e in own]}")

    # --- X-Ray: the traced execution's trace resolves at X-Ray -----------------------------
    header = resp.get("traceHeader")
    assert header, (
        "a synchronous Express execution of a CMK-encrypted, tracingConfiguration.enabled=true "
        f"state machine must return a traceHeader; the response carried {header!r}"
    )
    root = _root_trace_id(header)
    assert root == own_root, (
        f"StartSyncExecution must echo back the supplied Root id; sent {own_root!r}, got {header!r}"
    )
    trace = _await_trace(xray, root)
    assert "Segments" in trace and trace["Segments"], (
        f"X-Ray must hold a non-empty trace for {root}; got {trace!r}"
    )
    segments = [json.loads(s["Document"]) for s in trace["Segments"]]
    origins = {s.get("origin") for s in segments}
    assert "AWS::StepFunctions::StateMachine" in origins, (
        f"the trace must carry a segment with origin AWS::StepFunctions::StateMachine; "
        f"got origins {sorted(o for o in origins if o)}"
    )


# ===== helpers =====

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

_DEFINITION = json.dumps({
    "StartAt": "Whoami",
    "States": {
        "Whoami": {
            "Type": "Task",
            "Resource": "arn:aws:states:::aws-sdk:sts:getCallerIdentity",
            "Parameters": {},
            "ResultSelector": {"account.$": "$.Account"},
            "End": True,
        }
    },
})

_XRAY_ACTIONS = [
    "xray:PutTraceSegments", "xray:PutTelemetryRecords",
    "xray:GetSamplingRules", "xray:GetSamplingTargets",
]

_LOG_ACTIONS = [
    "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
    "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
    "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    "logs:CreateLogStream", "logs:PutLogEvents",
]


def _key(ctx, kms, account: str) -> dict:
    """A CMK whose policy grants the account root full control (so IAM policies on the
    execution role govern it) plus the one statement CMK-encrypted logging needs: the log
    delivery service principal may decrypt."""
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "RootAccess", "Effect": "Allow",
             "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
             "Action": "kms:*", "Resource": "*"},
            {"Sid": "EnableLogServiceDelivery", "Effect": "Allow",
             "Principal": {"Service": "delivery.logs.amazonaws.com"},
             "Action": "kms:Decrypt", "Resource": "*"},
        ],
    })
    meta = kms.create_key(
        Description=f"sim2real-behav-sfn-cmk {CHECK[:180]}",
        KeyUsage="ENCRYPT_DECRYPT", Policy=policy,
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta


def _role(ctx, key_arn: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfncmk-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real-behav: sfn CMK logging+tracing execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    statements = [
        {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
         "Resource": key_arn},
        {"Effect": "Allow", "Action": _XRAY_ACTIONS, "Resource": "*"},
        {"Effect": "Allow", "Action": _LOG_ACTIONS, "Resource": "*"},
        {"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"},
    ]
    iam.put_role_policy(
        RoleName=name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return arn


def _log_group(ctx, account: str) -> tuple[str, str]:
    logs = ctx.client("logs")
    name = ctx.unique_name("/aws/vendedlogs/states/sim2real-behav-sfncmk-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK[:250]})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name, f"arn:aws:logs:{ctx.region}:{account}:log-group:{name}:*"


def _state_machine(ctx, sfn, role_arn: str, key_arn: str, group_arn: str) -> str:
    name = ctx.unique_name("sim2real-behav-sfncmk-")
    deadline = time.monotonic() + 150.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_DEFINITION, roleArn=role_arn, type="EXPRESS",
                encryptionConfiguration={
                    "type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_arn,
                    "kmsDataKeyReusePeriodSeconds": 60,
                },
                loggingConfiguration={
                    "level": "ALL", "includeExecutionData": True,
                    "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": group_arn}}],
                },
                tracingConfiguration={"enabled": True},
                tags=[{"key": "sim2real", "value": CHECK[:250]}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
            continue
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return arn
    raise AssertionError(f"CreateStateMachine still AccessDenied after 150s: {last!r}")


# StartSyncExecution calls KMS and X-Ray as the execution role; until the role's policy and
# the CMK's own key-policy grant both propagate, it fails for several different transient
# reasons that are not the behavior under test.
_PROPAGATION_MARKERS = (
    "KmsAccessDeniedException", "not authorized to assume", "AccessDenied",
    "security token included in the request is invalid",
)


def _sync(ctx, sfn, sm_arn: str, marker: str, trace_root: str, *, deadline: float) -> dict:
    """One StartSyncExecution, retrying only the transient role/key-policy propagation
    errors a freshly created role and CMK key policy can still raise."""
    kwargs = dict(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps({"marker": marker}), traceHeader=f"Root={trace_root};Sampled=1",
    )
    resp = sfn.start_sync_execution(**kwargs)
    while time.monotonic() < deadline:
        blob = (resp.get("cause") or "") + (resp.get("error") or "")
        if resp["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return resp
        time.sleep(_POLL_S)
        resp = sfn.start_sync_execution(**kwargs)
    return resp


def _warm_up_until_logged(ctx, sfn, sm_arn: str, group: str) -> tuple[dict, str, str, list[dict]]:
    """Run fresh synchronous executions, each with its own trace root and marker, until one
    SUCCEEDS and its complete history has reached the vended log group.

    CloudWatch Logs delivery for a log destination created in the last ~15-20s silently
    drops every record until the subscription itself finishes activating — an observable
    condition (the group holding nothing), never a fixed sleep standing in for it — so this
    retries whole fresh executions rather than polling one execution's own delivery.
    """
    deadline = time.monotonic() + _LOG_BUDGET_S
    last_status = None
    while time.monotonic() < deadline:
        root = _gen_trace_id()
        marker = ctx.unique_name("sim2real-mark-")
        resp = _sync(ctx, sfn, sm_arn, marker, root, deadline=deadline)
        last_status = resp["status"]
        if resp["status"] != "SUCCEEDED":
            continue
        exec_arn = resp["executionArn"]
        attempt_deadline = min(deadline, time.monotonic() + 20.0)
        own: list[dict] = []
        while time.monotonic() < attempt_deadline:
            own = _of(_read_group(ctx, group), exec_arn)
            if _complete(own):
                return resp, root, marker, own
            time.sleep(_POLL_S)
    raise AssertionError(
        f"no execution's complete history reached {group} within {_LOG_BUDGET_S}s; last "
        f"execution status was {last_status!r}"
    )


def _root_trace_id(header: str) -> str:
    match = _ROOT_RE.search(header)
    return match.group(1) if match else ""


def _gen_trace_id() -> str:
    return f"1-{int(time.time()):08x}-{os.urandom(12).hex()}"


def _read_group(ctx, group: str) -> list[dict]:
    logs = ctx.client("logs")
    out, kwargs = [], {"logGroupName": group, "limit": 10000}
    while True:
        try:
            resp = logs.filter_log_events(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return out
            raise
        for event in resp["events"]:
            if event["logStreamName"] == _VALIDATION_STREAM:
                continue
            try:
                out.append(json.loads(event["message"]))
            except ValueError:
                raise AssertionError(
                    f"non-JSON message in {group}/{event['logStreamName']}: "
                    f"{event['message'][:300]!r}") from None
        if not resp.get("nextToken"):
            return out
        kwargs["nextToken"] = resp["nextToken"]


def _of(events: list[dict], exec_arn: str) -> list[dict]:
    return sorted((e for e in events if e.get("execution_arn") == exec_arn),
                  key=lambda e: int(e["id"]))


def _complete(logged: list[dict]) -> bool:
    term = [int(e["id"]) for e in logged if e["type"] == "ExecutionSucceeded"]
    return bool(term) and {int(e["id"]) for e in logged} >= set(range(1, term[0] + 1))


def _await_trace(xray, root: str) -> dict:
    deadline = time.monotonic() + _XRAY_BUDGET_S
    unprocessed = None
    while time.monotonic() < deadline:
        resp = xray.batch_get_traces(TraceIds=[root])
        if resp["Traces"]:
            return resp["Traces"][0]
        unprocessed = resp["UnprocessedTraceIds"]
        time.sleep(_POLL_S)
    raise AssertionError(
        f"X-Ray never returned trace {root} within {_XRAY_BUDGET_S}s; "
        f"UnprocessedTraceIds was {unprocessed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
