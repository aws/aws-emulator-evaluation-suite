"""deploy-agent-runtime-invokable-via-cfn."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-agent-runtime-invokable-via-cfn"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore"]

_MAIN_PY = '''\
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/ping":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"healthy")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/invocations":
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(body or b"{}")
            except Exception:
                payload = {}
            data = json.dumps({"result": "sim2real-echo", "received": payload}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AgentCore runtime resource reaches CREATE_COMPLETE and is
    actually invokable via InvokeAgentRuntime against its deployed ARN."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")
    data = ctx.client("bedrock-agentcore")

    bucket = ctx.unique_name("sim2real-agentcore-rt-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)

    key = "sim2real/main.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("main.py", _MAIN_PY)
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())

    role_name = ctx.unique_name("sim2real-agentcore-rt-role-")[:64]
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-agentcore-rt-policy",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": f"arn:aws:s3:::{bucket}/{key}",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-agentcore-rt-policy")
        )
    )
    role_arn = _role_arn(iam, role_name)

    final = _create_runtime_stack_with_role_retry(ctx, cfn, bucket, key, role_arn)
    runtime_arn = next(o["OutputValue"] for o in final["Outputs"] if o["OutputKey"] == "RuntimeArn")

    # A per-run marker, not a fixed string: a stub that always answers the same canned body
    # would pass a fixed-string assertion without ever running the deployed code. Only a
    # container that actually executed main.py and echoed what it was sent can produce this.
    marker = ctx.unique_name("sim2real-agentcore-rt-invoke-")
    invoke_errors: list[str] = []
    try:
        invoked = _poll_until(
            lambda: _try_invoke(data, runtime_arn, marker, invoke_errors),
            lambda r: r is not None,
            timeout_s=280.0,
            interval_s=10.0,
        )
    except AssertionError as exc:
        raise AssertionError(f"{exc}; last invoke error={invoke_errors[-1] if invoke_errors else None!r}") from exc
    body = json.loads(invoked)
    assert body["result"] == "sim2real-echo", f"expected echo marker, got {body!r}"
    assert body["received"]["prompt"] == marker, (
        f"expected the deployed runtime to echo back {marker!r}, got {body['received']!r}"
    )


# ===== helpers =====
def _create_runtime_stack_with_role_retry(ctx, cfn, bucket: str, key: str, role_arn: str, *, attempts: int = 5):
    """Create the AgentCore::Runtime stack, retrying a failed create only when the failure names
    the role: a freshly created IAM role can briefly be unassumable by another service until its
    trust policy propagates, so the real dependent call is retried on that reason alone."""
    last_status = None
    last_reason = None
    for attempt in range(attempts):
        runtime_name = _sanitize(ctx.unique_name("sim2realruntimecfn"))
        stack_name = ctx.unique_name("sim2real-agentcore-runtime-stack-")
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Runtime": {
                    "Type": "AWS::BedrockAgentCore::Runtime",
                    "Properties": {
                        "AgentRuntimeName": runtime_name,
                        "RoleArn": role_arn,
                        "AgentRuntimeArtifact": {
                            "CodeConfiguration": {
                                "Code": {"S3": {"Bucket": bucket, "Prefix": key}},
                                "EntryPoint": ["main.py"],
                                "Runtime": "PYTHON_3_13",
                            }
                        },
                        "ProtocolConfiguration": "HTTP",
                        "NetworkConfiguration": {"NetworkMode": "PUBLIC"},
                    },
                }
            },
            "Outputs": {
                "RuntimeArn": {"Value": {"Fn::GetAtt": ["Runtime", "AgentRuntimeArn"]}}
            },
        }

        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(template),
            Capabilities=["CAPABILITY_IAM"],
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )
        ctx.on_cleanup(lambda sn=stack_name: _best_effort(lambda: cfn.delete_stack(StackName=sn)))

        final = _poll_until(
            lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0],
            lambda s: s["StackStatus"] in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"),
            timeout_s=600.0,
            interval_s=15.0,
        )
        if final["StackStatus"] == "CREATE_COMPLETE":
            return final

        last_status = final["StackStatus"]
        last_reason = _stack_failure_reason(cfn, stack_name)
        if attempt + 1 < attempts and _looks_like_role_propagation_failure(last_reason):
            time.sleep(2)
            continue
        break

    raise AssertionError(
        f"CloudFormation stack ended in {last_status!r} instead of CREATE_COMPLETE "
        f"(reason={last_reason!r}); AgentCore Runtime direct code deployment may not be "
        "available in this account/region."
    )


def _stack_failure_reason(cfn, stack_name: str) -> str | None:
    try:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    except Exception:
        return None
    # describe_stack_events returns newest-first, and the stack's own terminal event (a generic
    # "N error(s), call DescribeEvents" summary) is newer than the resource-level failure that
    # actually explains it — so prefer a non-stack (resource) reason over the stack's own.
    resource_reason = None
    stack_reason = None
    for event in events:
        if not (event.get("ResourceStatus", "").endswith("FAILED") and event.get("ResourceStatusReason")):
            continue
        if event.get("ResourceType") == "AWS::CloudFormation::Stack":
            stack_reason = stack_reason or event["ResourceStatusReason"]
        else:
            resource_reason = resource_reason or (
                f"{event.get('LogicalResourceId')} ({event.get('ResourceType')}): "
                f"{event['ResourceStatusReason']}"
            )
    return resource_reason or stack_reason


def _looks_like_role_propagation_failure(reason: str | None) -> bool:
    if not reason:
        return False
    lowered = reason.lower()
    return "role" in lowered and (
        "not authorized" in lowered
        or "assum" in lowered  # covers both "assume" and "assumption"
        or "access denied" in lowered
        or "trust policy" in lowered
    )


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: _best_effort(lambda: _empty_and_delete_bucket(s3, bucket)))


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _role_arn(iam, role_name: str) -> str:
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _sanitize(name: str) -> str:
    cleaned = "".join(c for c in name if c.isalnum() or c == "_")
    if not cleaned[:1].isalpha():
        cleaned = "r" + cleaned
    return cleaned[:48]


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchEntity", "NoSuchKey", "StackNotFoundException", "ValidationError") or (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" not in exc.response["Error"]["Message"]
        ):
            raise


def _try_invoke(data, runtime_arn: str, prompt: str, errors: list[str]):
    try:
        resp = data.invoke_agent_runtime(
            agentRuntimeArn=runtime_arn,
            payload=json.dumps({"prompt": prompt}).encode(),
            contentType="application/json",
            accept="application/json",
        )
        return resp["response"].read()
    except Exception as exc:
        errors.append(repr(exc))
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
