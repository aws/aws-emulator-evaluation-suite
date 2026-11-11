"""e2e-ab-test-traffic-routing-consequence."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-ab-test-traffic-routing-consequence"
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
    """An ABTest created with variant weights C=90/T1=10 reports them in GetABTest once ACTIVE,
    UpdateABTest to C=20/T1=80 is reflected there, and after DeleteABTest GetABTest returns
    ResourceNotFoundException ('AB test not found: abTestId=<id>').
    """
    data = ctx.client("bedrock-agentcore")

    try:
        gateway_arn, eval_arn, ab_test_role_arn = _build_ab_test_prerequisites(ctx)
    except AssertionError:
        raise
    except Exception as exc:  # pragma: no cover - defensive against control-plane drift
        raise AssertionError(f"setting up A/B test prerequisites failed: {exc!r}") from exc

    name = _sanitize(ctx.unique_name("sim2realabroute"))
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
                {"name": "C", "weight": 90, "variantConfiguration": {"target": {"name": "sim2real-route-c"}}},
                {"name": "T1", "weight": 10, "variantConfiguration": {"target": {"name": "sim2real-route-t"}}},
            ],
            enableOnCreate=False,
            clientToken=str(uuid.uuid4()),
            tags={"sim2real": CHECK},
        )
    )
    ab_test_id = created["abTestId"]
    ctx.on_cleanup(lambda: _ac_delete_ab_test(data, ab_test_id))

    active = _poll_until(
        lambda: data.get_ab_test(abTestId=ab_test_id),
        lambda r: r["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert active["status"] == "ACTIVE", f"expected ACTIVE after create, got {active['status']!r}"
    weights = {v["name"]: v["weight"] for v in active["variants"]}
    assert weights == {"C": 90, "T1": 10}, f"expected initial weights C=90/T1=10, got {weights!r}"

    data.update_ab_test(
        abTestId=ab_test_id,
        variants=[
            {"name": "C", "weight": 20, "variantConfiguration": {"target": {"name": "sim2real-route-c"}}},
            {"name": "T1", "weight": 80, "variantConfiguration": {"target": {"name": "sim2real-route-t"}}},
        ],
    )

    reweighted = _poll_until(
        lambda: data.get_ab_test(abTestId=ab_test_id),
        lambda r: r["status"] in ("ACTIVE", "UPDATE_FAILED"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert reweighted["status"] == "ACTIVE", f"expected ACTIVE after update, got {reweighted['status']!r}"
    new_weights = {v["name"]: v["weight"] for v in reweighted["variants"]}
    assert new_weights == {"C": 20, "T1": 80}, f"expected updated weights C=20/T1=80, got {new_weights!r}"

    data.delete_ab_test(abTestId=ab_test_id)
    error = _poll_until_gone(
        lambda: data.get_ab_test(abTestId=ab_test_id), timeout_s=120.0, interval_s=5.0
    )
    assert error.get("Code") == "ResourceNotFoundException", (
        "expected GetABTest on a deleted abTestId to eventually fail with ResourceNotFoundException, "
        f"got {error!r}"
    )
    expected_message = f"AB test not found: abTestId={ab_test_id}"
    assert error.get("Message") == expected_message, (
        f"expected GetABTest's not-found message {expected_message!r}, got {error.get('Message')!r}"
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


def _ac_delete_agent_runtime(control, runtime_id):
    _ac_delete_and_wait(
        lambda: control.get_agent_runtime(agentRuntimeId=runtime_id)["status"],
        lambda: control.delete_agent_runtime(agentRuntimeId=runtime_id),
        what=f"agent runtime {runtime_id}",
    )
def _build_ab_test_prerequisites(ctx):
    # CreateABTest refuses with "Log group 'aws/spans' was not found" unless X-Ray Transaction
    # Search is on in the account and region, so the check turns it on and restores it.
    _ensure_transaction_search_enabled(ctx)
    control = ctx.client("bedrock-agentcore-control")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    logs = ctx.client("logs")

    bucket = ctx.unique_name("sim2real-abroute-").lower().replace("_", "-")
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

    runtime_role_arn = _create_role(ctx, iam, "sim2real-abroute-rt-role-", ["logs:*", "s3:GetObject"])

    runtime_name = _sanitize(ctx.unique_name("sim2realabrtrte"))
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
            networkConfiguration={"networkMode": "PUBLIC"},
            protocolConfiguration={"serverProtocol": "HTTP"},
            tags={"sim2real": CHECK},
        )
    )
    runtime_arn = rt["agentRuntimeArn"]
    runtime_id = rt["agentRuntimeId"]
    ctx.on_cleanup(lambda: _ac_delete_agent_runtime(control, runtime_id))
    _poll_until(
        lambda: control.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r.get("status", "") not in ("CREATING",),
        timeout_s=180.0,
        interval_s=5.0,
    )

    log_group_name = ctx.unique_name("/sim2real/agentcore-abroute-eval")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _best_effort(lambda: logs.delete_log_group(logGroupName=log_group_name)))

    eval_role_arn = _create_role(ctx, iam, "sim2real-abroute-eval-role-", ["logs:*", "bedrock:InvokeModel*"])

    eval_name = _sanitize(ctx.unique_name("sim2realabrouteeval"))
    eval_cfg = _retry_role_propagation(
        lambda: control.create_online_evaluation_config(
            onlineEvaluationConfigName=eval_name,
            rule={"samplingConfig": {"samplingPercentage": 100.0}},
            dataSourceConfig={
                "cloudWatchLogs": {
                    "serviceNames": ["sim2real-abroute-service"],
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
    ctx.on_cleanup(lambda: _ac_delete_online_evaluation_config(control, eval_id))

    gateway_role_arn = _create_role(ctx, iam, "sim2real-abroute-gw-role-", ["bedrock-agentcore:*"])
    gw_name = ctx.unique_name("sim2real-abroute-gw")[:48]
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

    for target_name in ("sim2real-route-c", "sim2real-route-t"):
        tgt = control.create_gateway_target(
            gatewayIdentifier=gateway_id,
            name=target_name,
            targetConfiguration={"http": {"agentcoreRuntime": {"arn": runtime_arn, "qualifier": "DEFAULT"}}},
            clientToken=str(uuid.uuid4()),
        )
        target_id = tgt["targetId"]
        _poll_until(
            lambda tid=target_id: control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=tid),
            lambda r: r.get("status", "") not in ("CREATING",),
            timeout_s=120.0,
            interval_s=5.0,
        )

    ab_test_role_arn = _create_role(ctx, iam, "sim2real-abroute-role-", ["bedrock-agentcore:*", "logs:*"])
    return gateway_arn, eval_arn, ab_test_role_arn


def _create_role(ctx, iam, prefix: str, actions: list[str]) -> str:
    role_name = ctx.unique_name(prefix)[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"}, "Action": "sts:AssumeRole"}
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
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))
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


def _retry_role_propagation(fn, timeout_s=90.0, interval_s=5.0):
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


def _poll_until_gone(probe, *, timeout_s=120.0, interval_s=5.0):
    """Delete is asynchronous: GetABTest keeps answering with status DELETING (or the terminal
    DELETE_FAILED) until the resource is actually gone, so a single post-delete read cannot tell
    a slow-but-correct delete from one that never happened. Returns the refusal's Error dict."""
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            resp = probe()
        except ClientError as exc:
            return exc.response.get("Error", {})
        last_status = resp.get("status")
        if last_status == "DELETE_FAILED":
            raise AssertionError(f"DeleteABTest settled on DELETE_FAILED instead of removing {resp.get('abTestId')!r}")
        time.sleep(interval_s)
    raise AssertionError(f"AB test did not reach deleted/DELETE_FAILED within {timeout_s}s; last status={last_status!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")

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
