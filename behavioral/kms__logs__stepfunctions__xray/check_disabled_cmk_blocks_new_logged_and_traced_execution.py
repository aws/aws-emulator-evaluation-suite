"""disabled-cmk-blocks-new-logged-and-traced-execution."""
from __future__ import annotations

import json
import os
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disabled-cmk-blocks-new-logged-and-traced-execution"
GROUP = "cmk_encryption"
SERVICES = ["kms", "logs", "stepfunctions", "xray"]

_REUSE_S = 60
_LOG_BUDGET_S = 240.0
_LOG_ATTEMPT_S = 20.0
_XRAY_BUDGET_S = 420.0
_SAMPLE_RETRY_S = 1.1
_VALIDATION_STREAM = "log_stream_created_by_aws_to_validate_log_delivery_subscriptions"
# StartSyncExecution calls KMS and X-Ray as the execution role; until the role's policy and
# the CMK's key policy propagate, it fails for transient reasons that are not under test.
_PROPAGATION_MARKERS = (
    "KmsAccessDeniedException", "not authorized to assume", "AccessDenied",
    "security token included in the request is invalid",
)


@tags("axis:rejection", "dp:api", "plane:data", "cap:c3", "concern:negative-classes",
      "concern:e2e")
def run(ctx) -> None:
    """Disabling a state machine's CMK makes StartSyncExecution refuse a new execution with
    KmsInvalidStateException, and the refused start reaches neither CloudWatch Logs nor X-Ray
    for three times as long as an enabled-key run's log record and trace took to appear.
    """
    sfn = ctx.client("stepfunctions")
    kms = ctx.client("kms")
    xray = ctx.client("xray")
    account = ctx.client("sts").get_caller_identity()["Account"]

    key = _key(ctx, account)
    role_arn = _role(ctx, key["Arn"])
    group, group_arn = _log_group(ctx, account)
    sm_arn = _state_machine(ctx, sfn, role_arn, key["Arn"], group_arn)

    # --- Positive control: enabled key, the execution SUCCEEDS, is logged and is traced; the
    # time both signals take to appear sizes the absence window below. --------------------
    good, good_root, good_returned = _warm_up_until_logged(ctx, sfn, sm_arn, group)
    _await_state_machine_segment(ctx, xray, good_root)
    latency_s = time.monotonic() - good_returned

    # --- The negative: disable the key; a start is refused once the cached data key lapses -
    kms.disable_key(KeyId=key["KeyId"])
    state = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"DisableKey must leave the key Disabled; it is {state!r}"

    deadline = time.monotonic() + _REUSE_S + 60.0
    refused = None
    while refused is None:
        marker = ctx.unique_name("sim2real-mark-")
        root = _gen_trace_id()
        try:
            resp = sfn.start_sync_execution(
                stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
                input=json.dumps({"marker": marker}), traceHeader=f"Root={root};Sampled=1",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KmsInvalidStateException":
                raise
            refused = (exc, marker, root)
            break
        # Within the data key reuse period a start may still run on the cached data key.
        assert resp["status"] == "SUCCEEDED", (
            f"StartSyncExecution against the Disabled CMK must either still run on the cached "
            f"data key or be refused with KmsInvalidStateException; it returned "
            f"status={resp['status']!r} error={resp.get('error')!r} cause={resp.get('cause')!r}"
        )
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"StartSyncExecution against a Disabled CMK was never refused within "
                f"{_REUSE_S + 60.0:.0f}s of disabling it"
            )
        time.sleep(2.0)
    exc, refused_marker, refused_root = refused
    got_message = exc.response["Error"].get("Message") or ""
    expected = _kms_disabled_message(key["Arn"], got_message)
    assert got_message == expected, (
        f"StartSyncExecution must relay KMS's disabled-key message {expected!r}; "
        f"got {got_message!r}"
    )

    # --- The refused start never reaches CloudWatch Logs or X-Ray -------------------------
    hold_s = max(15.0, 3.0 * latency_s)
    hold_until = time.monotonic() + hold_s
    while True:
        logged = [e for e in _read_group(ctx, group) if refused_marker in json.dumps(e)]
        assert logged == [], (
            f"the log group must never hold the refused start; it held {logged!r}"
        )
        traced = xray.batch_get_traces(TraceIds=[refused_root])["Traces"]
        assert traced == [], (
            f"X-Ray must hold no trace for the refused start's root id {refused_root}; it "
            f"resolved {[t['Id'] for t in traced]}"
        )
        if time.monotonic() >= hold_until:
            break
        time.sleep(5.0)


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


def _key(ctx, account: str) -> dict:
    """A CMK whose policy grants the account root full control (so the execution role's IAM
    policy governs it) and lets the log delivery service decrypt, which CMK-encrypted
    logging needs."""
    kms = ctx.client("kms")
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
        Description=f"sim2real-behav-sfncmk-disabled {CHECK[:160]}",
        KeyUsage="ENCRYPT_DECRYPT", Policy=policy,
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:250]}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta


def _role(ctx, key_arn: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfncmk-disabled-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real-behav: sfn disabled-CMK execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    statements = [
        {"Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": key_arn},
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
    name = ctx.unique_name("/aws/vendedlogs/states/sim2real-behav-sfncmk-disabled-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK[:250]})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name, f"arn:aws:logs:{ctx.region}:{account}:log-group:{name}:*"


def _state_machine(ctx, sfn, role_arn: str, key_arn: str, group_arn: str) -> str:
    name = ctx.unique_name("sim2real-behav-sfncmk-disabled-")
    deadline = time.monotonic() + 150.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_DEFINITION, roleArn=role_arn, type="EXPRESS",
                encryptionConfiguration={
                    "type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_arn,
                    "kmsDataKeyReusePeriodSeconds": _REUSE_S,
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


def _sync(ctx, sfn, sm_arn: str, marker: str, trace_root: str, *, deadline: float) -> dict:
    kwargs = dict(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps({"marker": marker}), traceHeader=f"Root={trace_root};Sampled=1",
    )
    resp = sfn.start_sync_execution(**kwargs)
    while time.monotonic() < deadline:
        blob = (resp.get("cause") or "") + (resp.get("error") or "")
        if resp["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return resp
        time.sleep(2.0)
        resp = sfn.start_sync_execution(**kwargs)
    return resp


def _warm_up_until_logged(ctx, sfn, sm_arn: str, group: str) -> tuple[dict, str, float]:
    """Run fresh enabled-key executions until one SUCCEEDS, is sampled for X-Ray and has its
    complete history in the log group; return it, its trace root and when it returned.

    A just-created log destination drops records until its subscription activates, so each
    attempt is a whole fresh execution, not a longer wait on one execution's delivery. An
    execution X-Ray did not sample (its traceHeader carries Sampled=0) is never recorded, so
    it is replaced by a fresh one after the sampler's one-second reservoir window.
    """
    deadline = time.monotonic() + _LOG_BUDGET_S
    last = None
    while time.monotonic() < deadline:
        resp = _sync(ctx, sfn, sm_arn, ctx.unique_name("sim2real-mark-"), _gen_trace_id(),
                     deadline=deadline)
        assert resp["status"] == "SUCCEEDED", (
            f"with the key enabled the execution must SUCCEED; got {resp['status']!r} "
            f"error={resp.get('error')!r} cause={resp.get('cause')!r}"
        )
        returned = time.monotonic()
        fields = _trace_fields(resp.get("traceHeader") or "")
        assert fields.get("Root"), (
            f"a traced execution's StartSyncExecution response must carry a traceHeader with a "
            f"Root; got {resp.get('traceHeader')!r}"
        )
        if fields.get("Sampled", "1") != "1":
            last = resp.get("traceHeader")
            time.sleep(_SAMPLE_RETRY_S)
            continue
        root = fields["Root"]
        attempt_deadline = min(deadline, returned + _LOG_ATTEMPT_S)
        while True:
            last = _of(_read_group(ctx, group), resp["executionArn"])
            if _complete(last):
                return resp, root, returned
            if time.monotonic() >= attempt_deadline:
                break
            time.sleep(2.0)
    raise AssertionError(
        f"no enabled-key execution's complete history reached {group!r} within "
        f"{_LOG_BUDGET_S:.0f}s; the last attempt read {last!r} (its logged records, or the "
        f"traceHeader of an execution X-Ray did not sample)"
    )


def _of(events: list[dict], exec_arn: str) -> list[dict]:
    return sorted((e for e in events if e.get("execution_arn") == exec_arn),
                  key=lambda e: int(e["id"]))


def _complete(logged: list[dict]) -> bool:
    term = [int(e["id"]) for e in logged if e["type"] == "ExecutionSucceeded"]
    return bool(term) and {int(e["id"]) for e in logged} >= set(range(1, term[0] + 1))


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _trace_fields(header: str) -> dict:
    return dict(p.split("=", 1) for p in header.split(";") if "=" in p)


def _trace_documents(xray, trace_id: str) -> list[dict]:
    """Every segment document BatchGetTraces holds for one trace id, across all pages."""
    docs, kwargs = [], {"TraceIds": [trace_id]}
    while True:
        resp = xray.batch_get_traces(**kwargs)
        for trace in resp["Traces"]:
            if trace.get("Id") == trace_id:
                docs.extend(json.loads(s["Document"]) for s in trace.get("Segments", []))
        if not resp.get("NextToken"):
            return docs
        kwargs["NextToken"] = resp["NextToken"]


def _await_state_machine_segment(ctx, xray, trace_id: str) -> dict:
    """Poll BatchGetTraces until the trace holds its AWS::StepFunctions::StateMachine segment."""
    timeout_s = _budget_s(ctx, _XRAY_BUDGET_S)
    deadline = time.monotonic() + timeout_s
    origins: list = []
    while True:
        docs = _trace_documents(xray, trace_id)
        roots = [d for d in docs if d.get("origin") == "AWS::StepFunctions::StateMachine"]
        if roots:
            return roots[0]
        origins = [d.get("origin") for d in docs]
        if time.monotonic() >= deadline:
            break
        time.sleep(3.0)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"the enabled-key execution's X-Ray trace {trace_id} had no Step Functions segment "
            f"when the run budget ended; segment origins read {origins}; not graded")
    raise AssertionError(
        f"the enabled-key execution's X-Ray trace {trace_id} held no "
        f"AWS::StepFunctions::StateMachine segment within {timeout_s:.0f}s; segment origins "
        f"read {origins}")


def _gen_trace_id() -> str:
    return f"1-{int(time.time()):08x}-{os.urandom(12).hex()}"


def _kms_disabled_message(key_arn: str, actual: str) -> str:
    """The exact text Step Functions relays from KMS for a disabled key.

    The relayed KMS request id is the only per-call token; it is taken from the actual
    message and must parse as a UUID, everything else is fixed or this check's own key ARN.
    """
    _, _, tail = actual.partition("Request ID: ")
    request_id = tail[:36]
    try:
        uuid.UUID(request_id)
    except ValueError:
        request_id = "<a KMS request id>"
    return (
        f"{key_arn} is disabled. (Service: Kms, Status Code: 400, Request ID: {request_id}) "
        f"(SDK Attempt Count: 1)"
    )


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
        out.extend(json.loads(e["message"]) for e in resp["events"]
                   if e["logStreamName"] != _VALIDATION_STREAM)
        if not resp.get("nextToken"):
            return out
        kwargs["nextToken"] = resp["nextToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
