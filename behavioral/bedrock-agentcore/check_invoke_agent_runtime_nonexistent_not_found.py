"""invoke-agent-runtime-nonexistent-not-found."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "invoke-agent-runtime-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore"]

_MAIN_PY = '''\
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == "/ping" else 404)
        self.end_headers()

    def do_POST(self):
        if self.path != "/invocations":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b"{}"
        try:
            received = json.loads(body or b"{}")
        except Exception:
            received = {}
        data = json.dumps({"result": "sim2real-echo", "received": received}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With a deployed runtime answering InvokeAgentRuntime, a well-formed but nonexistent
    agentRuntimeArn returns ResourceNotFoundException ('No endpoint or agent found with qualifier
    ...') and a structurally invalid ARN returns ValidationException, each with its exact message.
    """
    agentcore = ctx.client("bedrock-agentcore")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    region = ctx.region
    payload = json.dumps({"prompt": "hello"}).encode("utf-8")

    # Positive control: a real, running runtime answers InvokeAgentRuntime successfully,
    # proving the account/target can serve this call before we test its refusals below.
    runtime_arn = _create_invokable_runtime(ctx)
    resp = agentcore.invoke_agent_runtime(
        agentRuntimeArn=runtime_arn,
        payload=payload,
        contentType="application/json",
        accept="application/json",
    )
    control_body = json.loads(resp["response"].read())
    assert control_body["result"] == "sim2real-echo", (
        f"positive control: expected the real runtime to echo, got {control_body!r}"
    )
    assert control_body["received"]["prompt"] == "hello", (
        f"positive control: runtime did not receive the posted payload, got {control_body!r}"
    )

    missing_runtime_arn = f"arn:aws:bedrock-agentcore:{region}:{account}:runtime/sim2realmissingrt-abc1234567"

    # Primary assertion: well-formed but nonexistent runtime ARN -> ResourceNotFoundException.
    code, message = _error(
        lambda: agentcore.invoke_agent_runtime(agentRuntimeArn=missing_runtime_arn, payload=payload)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"No endpoint or agent found with qualifier 'DEFAULT' for agent '{missing_runtime_arn}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Contrast: a structurally invalid ARN takes a different (validation) code path.
    contrast_code, contrast_message = _error(
        lambda: agentcore.invoke_agent_runtime(agentRuntimeArn="not-an-arn-at-all", payload=payload)
    )
    assert contrast_code == "ValidationException", (
        f"expected ValidationException for a malformed ARN, got {contrast_code}"
    )
    expected_contrast = (
        "accountID is required when agentRuntimeArn is provided as agentId instead of agentRuntimeArn"
    )
    assert contrast_message == expected_contrast, (
        f"expected message {expected_contrast!r}, got {contrast_message!r}"
    )


def _create_invokable_runtime(ctx) -> str:
    control = ctx.client("bedrock-agentcore-control")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-invoke-nf-").lower().replace("_", "-")
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

    role_name = ctx.unique_name("sim2real-invoke-nf-role-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))
    policy_name = "sim2real-invoke-nf-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "s3:GetObject"],
                "Resource": "*",
            }],
        }),
    )
    ctx.on_cleanup(
        lambda: _best_effort(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )

    runtime_name = _sanitize(ctx.unique_name("sim2realinvnf"))
    rt = _retry_role_propagation(lambda: control.create_agent_runtime(
        agentRuntimeName=runtime_name,
        roleArn=iam.get_role(RoleName=role_name)["Role"]["Arn"],
        agentRuntimeArtifact={
            "codeConfiguration": {
                "code": {"s3": {"bucket": bucket, "prefix": key}},
                "entryPoint": ["main.py"],
                "runtime": "PYTHON_3_13",
            }
        },
        networkConfiguration={"networkMode": "PUBLIC"},
        protocolConfiguration={"serverProtocol": "HTTP"},
        tags={"sim2real-check": CHECK},
    ))
    runtime_id = rt["agentRuntimeId"]
    runtime_arn = rt["agentRuntimeArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: control.delete_agent_runtime(agentRuntimeId=runtime_id)))

    state = _poll_until(
        lambda: control.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r["status"] not in ("CREATING",),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert state["status"] == "READY", f"runtime never reached READY (status={state['status']!r})"
    return runtime_arn


def _retry_role_propagation(fn, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("AccessDeniedException", "ValidationException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _sanitize(name: str) -> str:
    cleaned = "".join(c for c in name if c.isalnum() or c == "_")
    if not cleaned[:1].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:48]


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


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


def _error(fn):
    """The (code, message) of the ClientError fn raises. An unexpected SUCCESS raises, so a
    target that accepts what AWS refuses fails naming what it returned."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
