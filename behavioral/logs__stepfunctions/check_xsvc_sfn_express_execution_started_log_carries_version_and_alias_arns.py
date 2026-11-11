"""xsvc-sfn-express-execution-started-log-carries-version-and-alias-arns."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-express-execution-started-log-carries-version-and-alias-arns"
GROUP = "express_execution_logging"
SERVICES = ["logs", "stepfunctions"]

_N_ALIAS = 6


@tags("axis:happy-path", "dp:api", "plane:data", "cap:c3", "concern:e2e")
def run(ctx) -> None:
    """An EXPRESS execution's ExecutionStarted log event carries stateMachineVersionArn when
    started by a version ARN, and both stateMachineAliasArn and the version the alias routed
    it to, the one whose definition it ran, when started by a two-version weighted alias ARN.
    """
    role_arn = _role(ctx)
    group, group_arn = _log_group(ctx)
    sm_arn, v1 = _create_published(ctx, role_arn, "v1", group_arn)
    v2 = ctx.client("stepfunctions").update_state_machine(
        stateMachineArn=sm_arn, definition=_definition("v2"), publish=True,
    )["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: ctx.client("stepfunctions").delete_state_machine_version(
        stateMachineVersionArn=v2))
    alias_arn = ctx.client("stepfunctions").create_state_machine_alias(
        name="live", description="sim2real 50/50",
        routingConfiguration=[{"stateMachineVersionArn": v1, "weight": 50},
                              {"stateMachineVersionArn": v2, "weight": 50}],
    )["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: ctx.client("stepfunctions").delete_state_machine_alias(
        stateMachineAliasArn=alias_arn))
    assert alias_arn == f"{sm_arn}:live", f"alias ARN {alias_arn!r} is not {sm_arn}:live"

    _warm_up(ctx, sm_arn, group)

    version_arn = _start(ctx, v1)
    alias_arns = [_start(ctx, alias_arn) for _ in range(_N_ALIAS)]

    want_terminal = [version_arn] + alias_arns
    events = _await(ctx, group, want_terminal)

    v_started = _started_details(events, version_arn)
    assert v_started.get("stateMachineVersionArn") == v1, (
        f"version-ARN-started execution must log stateMachineVersionArn={v1!r}: {v_started!r}")
    assert "stateMachineAliasArn" not in v_started, (
        f"version-ARN-started execution must carry no stateMachineAliasArn: {v_started!r}")

    result_of = {v1: "v1", v2: "v2"}
    for arn in alias_arns:
        d = _started_details(events, arn)
        assert d.get("stateMachineAliasArn") == alias_arn, (
            f"alias-ARN-started execution must log stateMachineAliasArn={alias_arn!r}: {d!r}")
        ver = d.get("stateMachineVersionArn")
        assert ver in result_of, f"alias-ARN-started execution routed to {ver!r}, not v1/v2: {d!r}"
        output = json.loads(_succeeded_details(events, arn)["output"])
        assert output == result_of[ver], (
            f"the execution logged as routed to {ver!r} must have run that version's definition "
            f"(output {result_of[ver]!r}); its logged output was {output!r}")


_LOG_BUDGET_S = 240.0
_POLL_S = 4.0
_VALIDATION_STREAM = "log_stream_created_by_aws_to_validate_log_delivery_subscriptions"

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

_LOG_ACTIONS = [
    "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
    "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
    "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    "logs:CreateLogStream", "logs:PutLogEvents",
]


def _definition(result: str) -> str:
    return json.dumps({"StartAt": "Mark", "States": {
        "Mark": {"Type": "Pass", "Result": result, "End": True}}})


def _role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-sfn-verlog-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real-xsvc: sfn express version/alias logging",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="logs",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": _LOG_ACTIONS, "Resource": "*"}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="logs"))
    return arn


def _log_group(ctx) -> tuple[str, str]:
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("/aws/vendedlogs/states/sim2real-xsvc-sfn-verlog-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK[:250]})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name, f"arn:aws:logs:{ctx.region}:{account}:log-group:{name}:*"


def _create_published(ctx, role_arn: str, result: str, group_arn: str) -> tuple[str, str]:
    """CreateStateMachine (EXPRESS, published), retrying only the AccessDeniedException
    raised while the new role's trust propagates — IAM exposes no condition to poll."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-xsvc-sfn-verlog-")[:80]
    logging = {"level": "ALL", "includeExecutionData": True,
               "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": group_arn}}]}
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name, definition=_definition(result), roleArn=role_arn, type="EXPRESS",
                publish=True, loggingConfiguration=logging,
                tags=[{"key": "sim2real", "value": CHECK[:250]}],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(5.0)
            continue
        sm_arn, v1 = resp["stateMachineArn"], resp["stateMachineVersionArn"]
        ctx.on_cleanup(lambda a=sm_arn: sfn.delete_state_machine(stateMachineArn=a))
        ctx.on_cleanup(lambda a=v1: sfn.delete_state_machine_version(stateMachineVersionArn=a))
        return sm_arn, v1
    raise AssertionError(f"CreateStateMachine still AccessDenied after 120s: {last}")


def _start(ctx, target_arn: str) -> str:
    return ctx.client("stepfunctions").start_execution(
        stateMachineArn=target_arn, input="{}")["executionArn"]


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


def _started_details(events: list[dict], exec_arn: str) -> dict:
    hits = [e for e in _of(events, exec_arn) if e["type"] == "ExecutionStarted"]
    assert len(hits) == 1, f"{exec_arn}: expected one ExecutionStarted, got {hits!r}"
    return hits[0]["details"]


def _succeeded_details(events: list[dict], exec_arn: str) -> dict:
    hits = [e for e in _of(events, exec_arn) if e["type"] == "ExecutionSucceeded"]
    assert len(hits) == 1, f"{exec_arn}: expected one ExecutionSucceeded, got {hits!r}"
    return hits[0]["details"]


def _await(ctx, group: str, exec_arns: list[str]) -> list[dict]:
    deadline = time.monotonic() + _LOG_BUDGET_S
    events: list[dict] = []
    while time.monotonic() < deadline:
        events = _read_group(ctx, group)
        if all(any(e.get("execution_arn") == a and e["type"] == "ExecutionSucceeded"
                   for e in events) for a in exec_arns):
            return events
        time.sleep(_POLL_S)
    raise AssertionError(
        f"not every execution's ExecutionSucceeded reached {group} within {_LOG_BUDGET_S}s; "
        f"wanted {exec_arns!r}")


def _warm_up(ctx, sm_arn: str, group: str) -> None:
    """Start executions until one is fully delivered; executions started in the first seconds
    after the log delivery is created are never delivered, while later ones are."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + _LOG_BUDGET_S
    started: list[str] = []
    while time.monotonic() < deadline:
        started.append(sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"])
        until = time.monotonic() + 12.0
        while time.monotonic() < until:
            events = _read_group(ctx, group)
            if any(any(e.get("execution_arn") == arn and e["type"] == "ExecutionSucceeded"
                       for e in events) for arn in started):
                return
            time.sleep(_POLL_S)
    raise AssertionError(
        f"log delivery to {group} never delivered one complete warm-up execution within "
        f"{_LOG_BUDGET_S}s across {len(started)} async executions")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
