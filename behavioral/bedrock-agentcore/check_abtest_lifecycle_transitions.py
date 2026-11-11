"""abtest-lifecycle-transitions."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "abtest-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore"]

_MAIN_PY = '''\
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == "/ping" else 404)
        self.end_headers()

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"result": "ok"}')

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """CreateABTest moves to an active state readable via GetABTest, UpdateABTest mutates
    it in place, and DeleteABTest makes subsequent GetABTest return ResourceNotFoundException."""
    data = ctx.client("bedrock-agentcore")

    try:
        gateway_arn, eval_arn, ab_test_role_arn = _build_ab_test_prerequisites(ctx)
    except AssertionError:
        raise
    except Exception as exc:  # pragma: no cover - defensive against control-plane drift
        raise AssertionError(
            f"setting up A/B test prerequisites failed: {exc!r}. Requires "
            "bedrock-agentcore-control (CreateAgentRuntime/CreateOnlineEvaluationConfig/"
            "CreateGateway/CreateGatewayTarget) to succeed end-to-end."
        ) from exc

    name = _sanitize(ctx.unique_name("sim2realabtest"))
    created = _retry_role_propagation(
        lambda: data.create_ab_test(
            name=name,
            gatewayArn=gateway_arn,
            roleArn=ab_test_role_arn,
            evaluationConfig={
                "perVariantOnlineEvaluationConfig": [
                    {"name": "C", "onlineEvaluationConfigArn": eval_arn},
                    {"name": "T1", "onlineEvaluationConfigArn": eval_arn},
                ]
            },
            variants=[
                {"name": "C", "weight": 50, "variantConfiguration": {"target": {"name": "sim2real-control"}}},
                {"name": "T1", "weight": 50, "variantConfiguration": {"target": {"name": "sim2real-treatment"}}},
            ],
            enableOnCreate=False,
            clientToken=str(uuid.uuid4()),
            tags={"sim2real": CHECK},
        ),
        timeout_s=150.0,
    )
    ab_test_id = created["abTestId"]
    ctx.on_cleanup(
        lambda: _ac_delete_and_wait(
            lambda: data.get_ab_test(abTestId=ab_test_id)["status"],
            lambda: data.delete_ab_test(abTestId=ab_test_id),
            what=f"A/B test {ab_test_id}",
        )
    )
    assert created["name"] == name, f"expected name {name!r}, got {created['name']!r}"
    assert created["executionStatus"] == "NOT_STARTED", (
        f"expected executionStatus NOT_STARTED on create (enableOnCreate=False), "
        f"got {created['executionStatus']!r}"
    )

    active = _poll_until(
        lambda: data.get_ab_test(abTestId=ab_test_id),
        lambda r: r["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert active["status"] == "ACTIVE", f"expected ACTIVE, got {active['status']!r}"
    assert active["abTestId"] == ab_test_id, (
        f"GetABTest returned a different abTestId: expected {ab_test_id!r}, got {active['abTestId']!r}"
    )
    assert active["executionStatus"] == "NOT_STARTED", (
        f"expected executionStatus to remain NOT_STARTED once ACTIVE (enableOnCreate=False), "
        f"got {active['executionStatus']!r}"
    )

    updated = data.update_ab_test(abTestId=ab_test_id, description="sim2real updated description")
    assert updated["abTestId"] == ab_test_id, (
        f"UpdateABTest returned a different abTestId: expected {ab_test_id!r}, got {updated['abTestId']!r}"
    )
    after_update = _poll_until(
        lambda: data.get_ab_test(abTestId=ab_test_id),
        lambda r: r["status"] in ("ACTIVE", "UPDATE_FAILED"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert after_update["status"] == "ACTIVE", f"expected ACTIVE after update, got {after_update['status']!r}"
    assert after_update["description"] == "sim2real updated description", (
        f"UpdateABTest's description mutation did not read back: got {after_update['description']!r}"
    )

    data.delete_ab_test(abTestId=ab_test_id)
    error = _poll_until_not_found(lambda: data.get_ab_test(abTestId=ab_test_id))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, last observed error={error!r}"
    )
    expected_message = f"AB test not found: abTestId={ab_test_id}"
    assert error.get("Message") == expected_message, (
        f"expected GetABTest's not-found message {expected_message!r}, got {error.get('Message')!r}"
    )


# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously. The
# runner swallows a cleanup's exception, so a bare delete in on_cleanup leaked even on PASS.
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


def _build_ab_test_prerequisites(ctx):
    control = ctx.client("bedrock-agentcore-control")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    logs = ctx.client("logs")

    # AB-test evaluation runs a CloudWatch Logs Insights query against the account-global
    # `aws/spans` log group that X-Ray Transaction Search populates. It is an account/region
    # singleton (like the Config recorder) — adopt it if already on, never turn it off, since
    # other concurrent runs may depend on it too.
    _ensure_transaction_search_enabled(ctx)

    bucket = ctx.unique_name("sim2real-abtest-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _best_effort(lambda: _empty_and_delete_bucket(s3, bucket)))
    key = "sim2real/main.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("main.py", _MAIN_PY)
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())

    runtime_role_arn = _create_role(ctx, iam, "sim2real-abtest-rt-role-", ["logs:*", "s3:GetObject"])

    runtime_name = _sanitize(ctx.unique_name("sim2realabrt"))
    rt = _retry_role_propagation(
        lambda: control.create_agent_runtime(
            agentRuntimeName=runtime_name,
            roleArn=runtime_role_arn,
            agentRuntimeArtifact={
                "codeConfiguration": {
                    "code": {"s3": {"bucket": bucket, "prefix": key}},
                    "entryPoint": ["main.py"],
                    "runtime": "PYTHON_3_13",
                }
            },
            protocolConfiguration={"serverProtocol": "HTTP"},
            networkConfiguration={"networkMode": "PUBLIC"},
            tags={"sim2real": CHECK},
        )
    )
    runtime_arn = rt["agentRuntimeArn"]
    runtime_id = rt["agentRuntimeId"]
    ctx.on_cleanup(
        lambda: _ac_delete_and_wait(
            lambda: control.get_agent_runtime(agentRuntimeId=runtime_id)["status"],
            lambda: control.delete_agent_runtime(agentRuntimeId=runtime_id),
            what=f"agent runtime {runtime_id}",
        )
    )
    _poll_until(
        lambda: control.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r.get("status", "") not in ("CREATING",),
        timeout_s=180.0,
        interval_s=5.0,
    )

    log_group_name = ctx.unique_name("/sim2real/agentcore-abtest-eval")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _best_effort(lambda: logs.delete_log_group(logGroupName=log_group_name)))

    eval_role_arn = _create_role(ctx, iam, "sim2real-abtest-eval-role-", ["logs:*", "bedrock:InvokeModel*"])

    eval_name = _sanitize(ctx.unique_name("sim2realabeval"))
    eval_cfg = _retry_role_propagation(
        lambda: control.create_online_evaluation_config(
            onlineEvaluationConfigName=eval_name,
            rule={"samplingConfig": {"samplingPercentage": 100.0}},
            dataSourceConfig={
                "cloudWatchLogs": {
                    "serviceNames": ["sim2real-abtest-service"],
                    "logGroupNames": [log_group_name],
                }
            },
            evaluators=[{"evaluatorId": "Builtin.Helpfulness"}],
            evaluationExecutionRoleArn=eval_role_arn,
            enableOnCreate=False,
            tags={"sim2real": CHECK},
        )
    )
    eval_arn = eval_cfg["onlineEvaluationConfigArn"]
    eval_id = eval_cfg["onlineEvaluationConfigId"]
    ctx.on_cleanup(
        lambda: _ac_delete_and_wait(
            lambda: control.get_online_evaluation_config(onlineEvaluationConfigId=eval_id)["status"],
            lambda: control.delete_online_evaluation_config(onlineEvaluationConfigId=eval_id),
            what=f"online evaluation config {eval_id}",
        )
    )

    gateway_role_arn = _create_role(ctx, iam, "sim2real-abtest-gw-role-", ["bedrock-agentcore:*"])
    gw_name = ctx.unique_name("sim2real-abtest-gw")[:48]
    gw = _retry_role_propagation(
        lambda: control.create_gateway(
            name=gw_name,
            roleArn=gateway_role_arn,
            authorizerType="AWS_IAM",
            clientToken=str(uuid.uuid4()),
            tags={"sim2real": CHECK},
        )
    )
    gateway_id = gw["gatewayId"]
    gateway_arn = gw["gatewayArn"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(control, gateway_id))
    _poll_until(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id),
        lambda r: r.get("status", "") not in ("CREATING",),
        timeout_s=120.0,
        interval_s=5.0,
    )

    for target_name in ("sim2real-control", "sim2real-treatment"):
        tgt = control.create_gateway_target(
            gatewayIdentifier=gateway_id,
            name=target_name,
            targetConfiguration={
                "http": {"agentcoreRuntime": {"arn": runtime_arn, "qualifier": "DEFAULT"}}
            },
            clientToken=str(uuid.uuid4()),
        )
        target_id = tgt["targetId"]
        _poll_until(
            lambda tid=target_id: control.get_gateway_target(
                gatewayIdentifier=gateway_id, targetId=tid
            ),
            lambda r: r.get("status", "") not in ("CREATING",),
            timeout_s=120.0,
            interval_s=5.0,
        )

    ab_test_role_arn = _create_role(
        ctx,
        iam,
        "sim2real-abtest-role-",
        ["bedrock-agentcore:*", "logs:StartQuery", "logs:GetQueryResults"],
    )
    return gateway_arn, eval_arn, ab_test_role_arn


def _ensure_transaction_search_enabled(ctx) -> None:
    logs = ctx.client("logs")

    # X-Ray needs a CloudWatch Logs resource policy granting it PutLogEvents on aws/spans
    # before the destination will go ACTIVE. Account/region singleton like the setting itself —
    # upsert under our own fixed policy name instead of adding a duplicate, and delete it (and
    # restore the destination) in cleanup.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy_doc = {
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
    logs.put_resource_policy(
        policyName="sim2real-abtest-xray-transaction-search",
        policyDocument=json.dumps(policy_doc),
    )
    ctx.on_cleanup(lambda: _safe_delete_resource_policy(logs, "sim2real-abtest-xray-transaction-search"))


    _pin_trace_segment_destination(ctx, "CloudWatchLogs")


def _create_role(ctx, iam, prefix: str, actions: list[str]) -> str:
    role_name = ctx.unique_name(prefix)[:64]
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))
    policy_name = "sim2real-inline-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(
        lambda: _best_effort(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _sanitize(name: str) -> str:
    cleaned = "".join(c for c in name if c.isalnum() or c == "_")
    if not cleaned[:1].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:48]


def _retry_role_propagation(fn, *, timeout_s=60.0, interval_s=5.0):
    """IAM role trust-policy propagation is eventually consistent; retry the first call
    that depends on a just-created role until AWS honors it or the deadline passes."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchBucket",
            "NoSuchEntity",
            "NoSuchKey",
            "ResourceNotFoundException",
        ):
            raise


def _poll_until_not_found(fn, *, timeout_s=60.0, interval_s=5.0):
    """DeleteABTest can leave the resource in DELETING before GetABTest refuses it. Return the
    botocore Error dict of the refusal; a read that still SUCCEEDS at the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            if error.get("Code") == "ResourceNotFoundException" or time.monotonic() >= deadline:
                return error
        else:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"expected a refusal after delete, but the read still SUCCEEDS after {timeout_s}s "
                    f"and returned status={result.get('status')!r}"
                )
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


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
