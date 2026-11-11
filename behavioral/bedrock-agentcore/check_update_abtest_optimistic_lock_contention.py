"""update-abtest-optimistic-lock-contention."""
from __future__ import annotations

import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-abtest-optimistic-lock-contention"
GROUP = "concurrency"
SERVICES = ["bedrock-agentcore"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "plane:control",
    "resource:account-singleton:logs-resource-policy",
    "resource:account-singleton:xray-trace-segment-destination",
)
def run(ctx) -> None:
    """Two concurrent UpdateABTest calls on one ACTIVE AB test: at least one succeeds, every
    rejected one carries ConflictException, and GetABTest then returns the description of one of the
    successful writes.
    """
    iam = ctx.client("iam")
    control = ctx.client("bedrock-agentcore-control")
    agentcore = ctx.client("bedrock-agentcore")

    # Account/region prerequisite the AB-test control plane requires: X-Ray Transaction
    # Search, which is what creates the account-global `aws/spans` log group.
    _ensure_transaction_search_enabled(ctx)

    role_name = ctx.unique_name("sim2real-agentcore-gw-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    # The gateway, the AB test and the online-evaluation-config each need this role to hold
    # real permissions, not just the AssumeRole trust -- without it CreateABTest and
    # CreateOnlineEvaluationConfig are denied synchronously, never reaching the race this
    # check exercises.
    policy_name = "sim2real-inline-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "bedrock-agentcore:GetGateway",
                            "bedrock-agentcore:GetGatewayTarget",
                            "bedrock-agentcore:ListGatewayTargets",
                            "bedrock-agentcore:GetOnlineEvaluationConfig",
                            "bedrock-agentcore:GetEvaluator",
                        ],
                        "Resource": "*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:DescribeLogGroups",
                            "logs:FilterLogEvents",
                            "logs:GetLogEvents",
                            "logs:StartQuery",
                            "logs:GetQueryResults",
                            "logs:StopQuery",
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                            "logs:DescribeIndexPolicies",
                            "logs:PutIndexPolicy",
                        ],
                        "Resource": "*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
                        "Resource": "*",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )

    gateway_name = ("simrealgw" + uuid.uuid4().hex)[:40]

    def _create_gateway():
        return control.create_gateway(
            name=gateway_name,
            roleArn=role_arn,
            protocolType="MCP",
            authorizerType="NONE",
            tags={"sim2real-check": CHECK},
        )

    try:
        gw = _retry_role_propagation(_create_gateway)
    except ClientError as e:
        raise AssertionError(
            f"could not create a prerequisite Gateway ({e.response['Error']['Code']}); "
            "AB test optimistic locking cannot be exercised without a real ACTIVE AB test"
        )
    gateway_id = gw["gatewayId"]
    gateway_arn = gw["gatewayArn"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(control, gateway_id))

    if not _poll_gateway_ready(control, gateway_id, timeout_s=120):
        raise AssertionError(
            "Gateway never reached READY within 120s; skipping AB test race",
        )

    # CreateABTest validates that the gateway target(s) referenced by the variants and the
    # online-evaluation-config ARN both resolve to real resources -- a fabricated name/ARN is
    # rejected synchronously ("Gateway target(s) not found ...") before the race is ever reached.
    openapi_schema = json.dumps(
        {
            "openapi": "3.0.0",
            "info": {"title": "sim2real-behav-dummy", "version": "1.0.0"},
            "servers": [{"url": "https://example.com"}],
            "paths": {
                "/ping": {"get": {"operationId": "ping", "responses": {"200": {"description": "OK"}}}}
            },
        }
    )
    for target_name in ("simrealtargetc", "simrealtargett1"):
        _create_gateway_target(ctx, control, gateway_id, target_name, openapi_schema)

    eval_config_arn = _create_online_eval_config(ctx, control, role_arn)
    # Target-based variants (variantConfiguration.target, used below) require
    # perVariantOnlineEvaluationConfig -- the single onlineEvaluationConfigArn form is rejected
    # with "Target-based variants require perVariantOnlineEvaluationConfig".
    eval_config = {
        "perVariantOnlineEvaluationConfig": [
            {"name": "C", "onlineEvaluationConfigArn": eval_config_arn},
            {"name": "T1", "onlineEvaluationConfigArn": eval_config_arn},
        ]
    }
    variants = [
        {
            "name": "C",
            "weight": 50,
            "variantConfiguration": {"target": {"name": "simrealtargetc"}},
        },
        {
            "name": "T1",
            "weight": 50,
            "variantConfiguration": {"target": {"name": "simrealtargett1"}},
        },
    ]
    ab_name = ("simrealab" + uuid.uuid4().hex)[:40]

    def _create_ab_test():
        return agentcore.create_ab_test(
            name=ab_name,
            gatewayArn=gateway_arn,
            roleArn=role_arn,
            variants=variants,
            evaluationConfig=eval_config,
            tags={"sim2real-check": CHECK},
        )

    try:
        ab = _retry_role_propagation(_create_ab_test)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")
        raise AssertionError(
            f"could not create a prerequisite AB test ({code}: {message}); a real ACTIVE AB "
            "test needs the gateway role to additionally hold gateway-access permissions this "
            "check does not provision, so optimistic-lock contention cannot be exercised here"
        ) from e
    ab_test_id = ab["abTestId"]
    ctx.on_cleanup(lambda: _ac_delete_ab_test(agentcore, ab_test_id))

    status = _poll_ab_test_terminal(agentcore, ab_test_id, timeout_s=120)
    if status != "ACTIVE":
        raise AssertionError(
            f"AB test reached status={status} (not ACTIVE) within 120s; it references a "
            "gateway target and online-evaluation-config that this check cannot fully "
            "provision, so optimistic-lock contention on UpdateABTest cannot be exercised"
        )

    def _update(desc: str):
        try:
            agentcore.update_ab_test(abTestId=ab_test_id, description=desc)
            return ("ok", desc)
        except ClientError as e:
            return ("error", e.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(_update, "sim2real-update-a")
        f2 = pool.submit(_update, "sim2real-update-b")
        outcomes = [f1.result(), f2.result()]

    successes = [o for o in outcomes if o[0] == "ok"]
    conflicts = [o for o in outcomes if o[0] == "error" and o[1] == "ConflictException"]
    # UpdateABTest's ConflictException doc covers "trying to modify a resource that is
    # currently being modified by another request" -- a condition AWS MAY detect, not a
    # promise that two client threads overlapping on the server always produce one winner and
    # one loser: a target that serializes the race (both succeed) is correct too.
    assert len(successes) >= 1, f"expected at least one update to succeed, got {outcomes}"
    assert len(successes) + len(conflicts) == len(outcomes), (
        f"expected every rejected update to carry ConflictException, got {outcomes}"
    )

    # The mutating calls' own responses only prove the API accepted the write(s); the terminal
    # read is GetABTest (a different operation) confirming the persisted state matches one of
    # the actual successful writes.
    winner_descs = {desc for _, desc in successes}
    final = agentcore.get_ab_test(abTestId=ab_test_id)
    assert final.get("description") in winner_descs, (
        f"persisted AB test description={final.get('description')!r} does not match any "
        f"successful writer's update ({winner_descs!r}); an accepted write never reached "
        "the terminal read"
    )


# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously, so a
# teardown waits out the transitional status and then for ResourceNotFoundException.
_AC_TRANSITIONAL = ("CREATING", "UPDATING", "DELETING", "SYNCHRONIZING")


def _ac_delete_and_wait(get_status, delete, *, what, timeout_s=600.0, interval_s=5.0):
    """Delete once out of a transitional status, then wait for ResourceNotFound; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = get_status()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if last == "DELETED":
            return
        if last not in _AC_TRANSITIONAL:
            try:
                delete()
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ConflictException", "ValidationException"):
                    raise
                last = f"{last}; delete refused: {exc}"
        if time.monotonic() >= deadline:
            raise AssertionError(f"teardown: {what} still present after {timeout_s}s ({last})")
        time.sleep(interval_s)


def _ac_delete_gateway(control, gateway_id):
    """Delete every target first (DeleteGateway is refused while one exists), then the gateway."""
    try:
        pages = control.get_paginator("list_gateway_targets").paginate(gatewayIdentifier=gateway_id)
        target_ids = [t["targetId"] for page in pages for t in page.get("items", [])]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    for target_id in target_ids:
        _ac_delete_and_wait(
            lambda: control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)["status"],
            lambda: control.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
            what=f"gateway target {target_id}",
        )
    _ac_delete_and_wait(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id)["status"],
        lambda: control.delete_gateway(gatewayIdentifier=gateway_id),
        what=f"gateway {gateway_id}",
    )


def _ac_delete_ab_test(agentcore, ab_test_id):
    _ac_delete_and_wait(
        lambda: agentcore.get_ab_test(abTestId=ab_test_id)["status"],
        lambda: agentcore.delete_ab_test(abTestId=ab_test_id),
        what=f"AB test {ab_test_id}",
    )


def _ac_delete_online_evaluation_config(control, config_id):
    _ac_delete_and_wait(
        lambda: control.get_online_evaluation_config(onlineEvaluationConfigId=config_id)["status"],
        lambda: control.delete_online_evaluation_config(onlineEvaluationConfigId=config_id),
        what=f"online evaluation config {config_id}",
    )
def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _ensure_transaction_search_enabled(ctx) -> None:
    """Enable X-Ray Transaction Search (the account-global `aws/spans` log group the
    AB-test control plane requires): grant X-Ray PutLogEvents on it, then point the
    trace-segment destination at CloudWatchLogs. Both are account/region singletons shared
    with every other X-Ray check, so the existing destination is read first and its restore
    registered before the switch."""
    logs = ctx.client("logs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy_name = "sim2real-abtest-xray-transaction-search"
    logs.put_resource_policy(
        policyName=policy_name,
        policyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "TransactionSearchXRayAccess",
                        "Effect": "Allow",
                        "Principal": {"Service": "xray.amazonaws.com"},
                        "Action": "logs:PutLogEvents",
                        "Resource": [
                            "arn:aws:logs:*:*:log-group:aws/spans:*",
                            "arn:aws:logs:*:*:log-group:/aws/application-signals/data:*",
                        ],
                        "Condition": {
                            "ArnLike": {"aws:SourceArn": "arn:aws:xray:*:*:*"},
                            "StringEquals": {"aws:SourceAccount": account_id},
                        },
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_resource_policy(policyName=policy_name)))
    _pin_trace_segment_destination(ctx, "CloudWatchLogs")


def _pin_trace_segment_destination(ctx, want: str, *, timeout_s: float = 600.0) -> None:
    """Switch the account-wide trace-segment destination to `want` and register its restore
    in cleanup before doing so, so a switch that is refused or never settles is still undone."""
    xray = ctx.client("xray")
    original = _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"]
    ctx.on_cleanup(lambda: _restore_trace_segment_destination(xray, original, timeout_s=timeout_s))
    if original == want:
        return
    deadline = time.monotonic() + 120.0
    while True:
        try:
            xray.update_trace_segment_destination(Destination=want)
            break
        except ClientError as err:
            # A just-put logs resource policy takes a while to reach X-Ray, which until then
            # refuses CloudWatchLogs naming the PutLogEvents permission it cannot yet see.
            message = err.response["Error"].get("Message", "")
            if "PutLogEvents" not in message or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)
    current = _settled_trace_segment_destination(xray, timeout_s=timeout_s)
    assert current["Destination"] == want, (
        f"trace-segment destination settled on {current!r} instead of {want}/ACTIVE"
    )


def _settled_trace_segment_destination(xray, *, timeout_s: float) -> dict:
    # AWS refuses UpdateTraceSegmentDestination while a previous switch is still PENDING.
    deadline = time.monotonic() + timeout_s
    while True:
        current = xray.get_trace_segment_destination()
        if current.get("Status") == "ACTIVE":
            return current
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"trace-segment destination still not ACTIVE after {timeout_s}s: {current!r}"
            )
        time.sleep(2.0)


def _restore_trace_segment_destination(xray, original: str, *, timeout_s: float) -> None:
    """Cleanup: put the destination back and wait until it reads `original`/ACTIVE, so the
    next check starts from the account state this one found rather than from a PENDING switch."""
    if _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"] != original:
        xray.update_trace_segment_destination(Destination=original)
        _settled_trace_segment_destination(xray, timeout_s=timeout_s)


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    """Bounded retry for the window between IAM role creation and a dependent service
    being able to reference it — IAM propagation is eventually consistent, not instant."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _create_gateway_target(ctx, control, gateway_id: str, target_name: str, openapi_schema: str) -> None:
    def _create():
        return control.create_gateway_target(
            gatewayIdentifier=gateway_id,
            name=target_name,
            credentialProviderConfigurations=[
                {
                    "credentialProviderType": "GATEWAY_IAM_ROLE",
                    "credentialProvider": {"iamCredentialProvider": {"service": "execute-api"}},
                }
            ],
            targetConfiguration={"mcp": {"openApiSchema": {"inlinePayload": openapi_schema}}},
        )

    created = _retry_role_propagation(_create)
    target_id = created["targetId"]

    deadline = time.monotonic() + 60.0
    status = created.get("status", "CREATING")
    while status in ("CREATING", "UPDATING") and time.monotonic() < deadline:
        time.sleep(2)
        status = control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)["status"]
    assert status == "READY", (
        f"gateway target {target_name!r} settled on status={status!r} instead of READY "
        "within 60s"
    )


def _create_online_eval_config(ctx, control, role_arn: str) -> str:
    """AB test variants require an onlineEvaluationConfigArn that resolves to a real
    OnlineEvaluationConfig, validated synchronously the same as the gateway target names."""
    logs = ctx.client("logs")
    log_group_name = f"/sim2real/behav-{ctx.unique_name('abtest-evalcfg-')}"
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_log_group(logGroupName=log_group_name)))

    config_name = "Sim2realAbtestEvalCfg" + str(int(time.time() * 1000))[-10:]

    def _create():
        return control.create_online_evaluation_config(
            onlineEvaluationConfigName=config_name,
            evaluationExecutionRoleArn=role_arn,
            enableOnCreate=False,
            dataSourceConfig={
                "cloudWatchLogs": {
                    "serviceNames": ["Sim2realBehavAgent.DEFAULT"],
                    "logGroupNames": [log_group_name],
                }
            },
            evaluators=[{"evaluatorId": "Builtin.GoalSuccessRate"}],
            rule={"samplingConfig": {"samplingPercentage": 100}},
        )

    created = _retry_role_propagation(_create)

    config_id = created["onlineEvaluationConfigId"]
    ctx.on_cleanup(lambda: _ac_delete_online_evaluation_config(control, config_id))

    deadline = time.monotonic() + 60.0
    status = created.get("status", "CREATING")
    while status == "CREATING" and time.monotonic() < deadline:
        time.sleep(2)
        status = control.get_online_evaluation_config(onlineEvaluationConfigId=config_id)["status"]
    assert status == "ACTIVE", (
        f"online evaluation config {config_name!r} settled on status={status!r} instead of "
        "ACTIVE within 60s"
    )
    return created["onlineEvaluationConfigArn"]


def _poll_gateway_ready(control, gateway_id: str, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = control.get_gateway(gatewayIdentifier=gateway_id)
        if resp.get("status") == "READY":
            return True
        if resp.get("status") in ("FAILED",):
            return False
        time.sleep(5)
    return False


def _poll_ab_test_terminal(agentcore, ab_test_id: str, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last_status = "CREATING"
    while time.monotonic() < deadline:
        resp = agentcore.get_ab_test(abTestId=ab_test_id)
        last_status = resp.get("status")
        if last_status in ("ACTIVE", "CREATE_FAILED", "FAILED"):
            return last_status
        time.sleep(5)
    return last_status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
