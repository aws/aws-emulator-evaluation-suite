"""create-ab-test-duplicate-name-blocked."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-ab-test-duplicate-name-blocked"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """A second CreateABTest reusing the name of an existing AB test is refused with
    ConflictException and leaves the original unchanged; the first create (positive control)
    succeeds and stores the name lower-cased."""
    agentcore = ctx.client("bedrock-agentcore")
    # Account/region prerequisite the AB-test APIs require: X-Ray Transaction Search,
    # which is what creates the account-global `aws/spans` log group.
    _ensure_transaction_search_enabled(ctx)
    name = _alnum_name("Sim2realDupAbTest")
    role_arn = _create_ab_test_role(ctx)
    gateway_arn = _create_gateway(ctx, role_arn)
    eval_config_arn = _create_online_eval_config(ctx, role_arn)
    params = _build_ab_test_params(ctx, name, role_arn, gateway_arn, eval_config_arn)

    # Positive control: creating the first AB test with this name succeeds (retrying past
    # the IAM-assume-role eventual-consistency window right after role creation).
    created = _create_ab_test_with_retry(agentcore, params)
    ab_test_id = created["abTestId"]
    ctx.on_cleanup(
        lambda: _ac_delete_and_wait(
            lambda: agentcore.get_ab_test(abTestId=ab_test_id)["status"],
            lambda: agentcore.delete_ab_test(abTestId=ab_test_id),
            what=f"A/B test {ab_test_id}",
        )
    )
    assert created["name"] == name.lower(), (
        f"CreateABTest normalises the name to lower case; expected {name.lower()!r}, "
        f"got {created.get('name')!r}"
    )

    # Primary assertion: a second CreateABTest with the same name is blocked.
    code, message = _error(lambda: agentcore.create_ab_test(**params))
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected = f"AB test with name '{name}' already exists"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the original AB test is unaffected -- no second resource under the
    # same name was created, and the original's identity/name are unchanged.
    refetched = agentcore.get_ab_test(abTestId=ab_test_id)
    assert refetched["abTestId"] == ab_test_id
    assert refetched["name"] == name.lower(), refetched


# ===== helpers =====


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


def _ensure_transaction_search_enabled(ctx) -> None:
    """Enable X-Ray Transaction Search for this account/region, which is what creates the
    account-global ``aws/spans`` log group the AB-test APIs require.

    Provisioned in-check with logs:PutResourcePolicy for xray.amazonaws.com, then
    UpdateTraceSegmentDestination to CloudWatchLogs.

    Account/region singleton: the policy name is fixed and upserted rather than unique, and both
    the policy and the trace-segment destination are put back in cleanup. Leaving the destination
    on CloudWatchLogs is NOT harmless -- every X-Ray check that reads GetTraceSummaries then sees
    zero traces.
    """
    logs = ctx.client("logs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    logs.put_resource_policy(
        policyName="sim2real-abtest-xray-transaction-search",
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
    ctx.on_cleanup(lambda: _safe_delete_resource_policy(logs, "sim2real-abtest-xray-transaction-search"))


    _pin_trace_segment_destination(ctx, "CloudWatchLogs")


def _error(fn):
    """Call fn(); return the refusal's (code, message). A success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _alnum_name(prefix: str) -> str:
    suffix = str(int(time.time() * 1000))[-10:]
    return f"{prefix}{suffix}"


def _create_ab_test_role(ctx) -> str:
    """Provision a real IAM role trusting bedrock-agentcore.amazonaws.com so CreateABTest's
    synchronous AssumeRole check succeeds; the gateway/eval-config ARNs it references stay
    dummy since those are validated asynchronously, not at creation time."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-abtest-role-")
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    policy_name = "sim2real-behav-abtest-policy"
    permissions_policy = {
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
                    "bedrock-agentcore:GetConfigurationBundle",
                    "bedrock-agentcore:GetConfigurationBundleVersion",
                    "bedrock-agentcore:ListConfigurationBundleVersions",
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
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions_policy)
    )

    def _cleanup_role() -> None:
        from botocore.exceptions import ClientError

        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    return role_arn


def _create_ab_test_with_retry(agentcore, params: dict, timeout_s: float = 60.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return agentcore.create_ab_test(**params)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "").lower()
            if code == "ValidationException" and "assume" in message:
                last_err = err
                time.sleep(3)
                continue
            raise
    assert last_err is not None
    raise last_err


def _create_gateway(ctx, role_arn: str) -> str:
    """CreateABTest validates gatewayArn by looking the gateway up synchronously (it
    returns ValidationException("Gateway '...' was not found") rather than deferring
    that check), so a real (if otherwise unused) Gateway is required here."""
    control = ctx.client("bedrock-agentcore-control")
    from botocore.exceptions import ClientError

    gateway_name = ctx.unique_name("sim2real-behav-abtest-gw-")

    deadline = time.monotonic() + 60.0
    created = None
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            created = control.create_gateway(
                name=gateway_name, roleArn=role_arn, authorizerType="NONE"
            )
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "").lower()
            if code == "ValidationException" and "assume" in message:
                last_err = err
                time.sleep(3)
                continue
            raise
    if created is None:
        assert last_err is not None
        raise last_err

    gateway_id = created["gatewayId"]

    ctx.on_cleanup(lambda: _ac_delete_gateway(control, gateway_id))

    gw_deadline = time.monotonic() + 60.0
    status = created.get("status", "CREATING")
    while status == "CREATING" and time.monotonic() < gw_deadline:
        time.sleep(2)
        status = control.get_gateway(gatewayIdentifier=gateway_id)["status"]

    # CreateABTest also validates that the gateway target(s) referenced by the variants
    # exist ("Gateway target(s) not found on gateway ..."), so provision the two targets
    # ("target-c" / "target-t1") the variants below reference. A minimal inline OpenAPI
    # schema avoids needing any external Lambda/API resource.
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
    for target_name in ("target-c", "target-t1"):
        _create_gateway_target(control, ctx, gateway_id, target_name, openapi_schema)

    return created["gatewayArn"]


def _create_gateway_target(control, ctx, gateway_id: str, target_name: str, openapi_schema: str) -> None:
    created = control.create_gateway_target(
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

    deadline = time.monotonic() + 60.0
    status = created.get("status", "CREATING")
    while status in ("CREATING", "UPDATING") and time.monotonic() < deadline:
        time.sleep(2)
        status = control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=created["targetId"])["status"]


def _create_online_eval_config(ctx, role_arn: str) -> str:
    """Target-based AB test variants require perVariantOnlineEvaluationConfig entries whose
    onlineEvaluationConfigArn resolves to a real OnlineEvaluationConfig (validated
    synchronously, same as the gateway/target checks above)."""
    control = ctx.client("bedrock-agentcore-control")
    logs = ctx.client("logs")
    from botocore.exceptions import ClientError

    log_group_name = f"/sim2real/behav-{ctx.unique_name('abtest-evalcfg-')}"
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _best_effort_delete_log_group(logs, log_group_name))

    config_name = _alnum_name("Sim2realBehavEvalCfg")
    deadline = time.monotonic() + 60.0
    created = None
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            created = control.create_online_evaluation_config(
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
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "").lower()
            if code == "ValidationException" and "assume" in message:
                last_err = err
                time.sleep(3)
                continue
            if code == "ValidationException" and "security token is invalid" in message:
                # Same IAM propagation wall as the "cannot assume" arm, different wording: the
                # just-created execution role's session is not yet honoured.
                last_err = err
                time.sleep(3)
                continue
            if code == "ValidationException" and "log groups do not exist" in message:
                # The log group this function just created is eventually consistent from
                # CreateOnlineEvaluationConfig's point of view.
                last_err = err
                time.sleep(3)
                continue
            raise

    if created is None:
        assert last_err is not None
        raise last_err

    config_id = created["onlineEvaluationConfigId"]

    ctx.on_cleanup(
        lambda: _ac_delete_and_wait(
            lambda: control.get_online_evaluation_config(onlineEvaluationConfigId=config_id)["status"],
            lambda: control.delete_online_evaluation_config(onlineEvaluationConfigId=config_id),
            what=f"online evaluation config {config_id}",
        )
    )

    cfg_deadline = time.monotonic() + 60.0
    status = created.get("status", "CREATING")
    while status == "CREATING" and time.monotonic() < cfg_deadline:
        time.sleep(2)
        status = control.get_online_evaluation_config(onlineEvaluationConfigId=config_id)["status"]
    return created["onlineEvaluationConfigArn"]


def _best_effort_delete_log_group(logs, log_group_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        logs.delete_log_group(logGroupName=log_group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _build_ab_test_params(ctx, name: str, role_arn: str, gateway_arn: str, eval_config_arn: str) -> dict:
    return {
        "name": name,
        "gatewayArn": gateway_arn,
        "roleArn": role_arn,
        "variants": [
            {"name": "C", "weight": 50, "variantConfiguration": {"target": {"name": "target-c"}}},
            {"name": "T1", "weight": 50, "variantConfiguration": {"target": {"name": "target-t1"}}},
        ],
        "evaluationConfig": {
            "perVariantOnlineEvaluationConfig": [
                {"name": "C", "onlineEvaluationConfigArn": eval_config_arn},
                {"name": "T1", "onlineEvaluationConfigArn": eval_config_arn},
            ]
        },
    }


def _safe_delete_resource_policy(logs, policy_name: str) -> None:
    try:
        logs.delete_resource_policy(policyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _pin_trace_segment_destination(ctx, want: str, *, timeout_s: float = 600.0) -> str:
    """Set the account-wide trace-segment destination to `want` for the rest of this check and
    return the destination it found.

    The destination (XRay, or CloudWatchLogs for Transaction Search) is ONE setting per account
    and region, shared by every X-Ray check, and a switch takes ~6 minutes to go PENDING ->
    ACTIVE. A check that leaves it on CloudWatchLogs makes GetTraceSummaries return nothing for
    every other check, so the original is read first and its restore is registered BEFORE the
    switch: a switch that is refused or never settles is still undone."""
    from botocore.exceptions import ClientError

    xray = ctx.client("xray")
    original = _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"]
    ctx.on_cleanup(lambda: _restore_trace_segment_destination(xray, original, timeout_s=timeout_s))
    if original == want:
        return original
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
            time.sleep(2)
    current = _settled_trace_segment_destination(xray, timeout_s=timeout_s)
    assert current["Destination"] == want, (
        f"trace-segment destination settled on {current!r} instead of {want}/ACTIVE"
    )
    return original


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
        time.sleep(2)


def _restore_trace_segment_destination(xray, original: str, *, timeout_s: float) -> None:
    """Cleanup: put the destination back and WAIT until it reads `original`/ACTIVE, so the next
    check starts from the account state this one found rather than from a PENDING switch."""
    if _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"] != original:
        xray.update_trace_segment_destination(Destination=original)
        _settled_trace_segment_destination(xray, timeout_s=timeout_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

