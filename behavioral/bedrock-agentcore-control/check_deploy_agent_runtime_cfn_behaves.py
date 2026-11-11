"""deploy-agent-runtime-cfn-behaves."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import WaiterError

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-agent-runtime-cfn-behaves"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]

_APP_PY = """\
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
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(body)
            except ValueError:
                payload = {}
            resp = json.dumps({"echo": payload}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
"""

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  RuntimeDescription:
    Type: String
    Default: initial-deploy
Resources:
  ExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: bedrock-agentcore.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: sim2real-runtime-exec
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                Resource: '__CODE_OBJECT_ARN__'
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                  - bedrock-agentcore:*
                Resource: '*'
  AgentRuntime:
    Type: AWS::BedrockAgentCore::Runtime
    Properties:
      AgentRuntimeName: '__RUNTIME_NAME__'
      Description: !Ref RuntimeDescription
      RoleArn: !GetAtt ExecutionRole.Arn
      NetworkConfiguration:
        NetworkMode: PUBLIC
      AgentRuntimeArtifact:
        CodeConfiguration:
          Code:
            S3:
              Bucket: '__CODE_BUCKET__'
              Prefix: '__CODE_KEY__'
          Runtime: PYTHON_3_12
          EntryPoint:
            - app.py
Outputs:
  AgentRuntimeId:
    Value: !Ref AgentRuntime
  AgentRuntimeArn:
    Value: !GetAtt AgentRuntime.AgentRuntimeArn
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CloudFormation-deployed AgentRuntime reaches READY and actually serves invocations."""
    s3 = ctx.client("s3")
    control = ctx.client("bedrock-agentcore-control")
    data_plane = ctx.client("bedrock-agentcore")
    cfn = ctx.client("cloudformation")

    bucket_name = ctx.unique_name("sim2real-runtime-code-").lower()
    _create_bucket(ctx, s3, bucket_name)
    code_key = "app.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app.py", _APP_PY)
    s3.put_object(Bucket=bucket_name, Key=code_key, Body=buf.getvalue())

    runtime_name = _alnum_name(ctx, "sim2realCfnRuntime")
    template_body = (
        _TEMPLATE.replace("__CODE_OBJECT_ARN__", f"arn:aws:s3:::{bucket_name}/{code_key}")
        .replace("__RUNTIME_NAME__", runtime_name)
        .replace("__CODE_BUCKET__", bucket_name)
        .replace("__CODE_KEY__", code_key)
    )

    stack_name = _deploy_cfn(ctx, cfn, template_body)
    outputs = _stack_outputs(cfn, stack_name)
    runtime_id = outputs["AgentRuntimeId"]
    runtime_arn = outputs["AgentRuntimeArn"]

    ready = _poll_until(
        lambda: control.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r["status"] == "READY",
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert ready["agentRuntimeName"] == runtime_name, (
        f"expected agentRuntimeName={runtime_name!r}, got {ready['agentRuntimeName']!r}"
    )
    version1 = ready["agentRuntimeVersion"]

    session_id = uuid.uuid4().hex + uuid.uuid4().hex
    invoke_resp = data_plane.invoke_agent_runtime(
        agentRuntimeArn=runtime_arn,
        runtimeSessionId=session_id,
        payload=json.dumps({"prompt": "sim2real-ping"}).encode("utf-8"),
        contentType="application/json",
    )
    body = invoke_resp["response"].read()
    parsed = json.loads(body)
    echoed_prompt = parsed.get("echo", {}).get("prompt")
    assert echoed_prompt == "sim2real-ping", (
        f"expected invocation payload echoed back with prompt='sim2real-ping', got {parsed!r}"
    )

    cfn.update_stack(
        StackName=stack_name,
        UsePreviousTemplate=True,
        Parameters=[{"ParameterKey": "RuntimeDescription", "ParameterValue": "second-deploy"}],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    cfn.get_waiter("stack_update_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )
    updated = _poll_until(
        lambda: control.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r["status"] == "READY" and r["agentRuntimeVersion"] != version1,
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert updated["agentRuntimeVersion"] != version1, (
        f"expected agentRuntimeVersion to advance past {version1!r} after stack update, "
        f"got {updated['agentRuntimeVersion']!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )

    code, message = _error(lambda: control.get_agent_runtime(agentRuntimeId=runtime_id))
    assert code == "ResourceNotFoundException", (
        f"expected get_agent_runtime on a stack-deleted id to fail with ResourceNotFoundException, "
        f"got {code!r}"
    )
    expected = (
        f"Agent with agentId: {runtime_id}, accountId: {ctx.account}, and version: null not found!"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


# ===== helpers =====
def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch == "_")


def _create_bucket(ctx, s3, bucket_name: str) -> None:
    region = ctx.region
    if region and region != "us-east-1":
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    else:
        s3.create_bucket(Bucket=bucket_name)
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))


def _empty_and_delete_bucket(s3, bucket_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        resp = s3.list_objects_v2(Bucket=bucket_name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _failed_resources(cfn, stack_name: str) -> list[dict]:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    return [
        {
            "type": e["ResourceType"],
            "id": e["LogicalResourceId"],
            "status": e["ResourceStatus"],
            "reason": e.get("ResourceStatusReason", ""),
        }
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]


def _deploy_cfn(ctx, cfn, template_body: str) -> str:
    stack_name = ctx.unique_name("sim2real-agentruntime-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _destroy_stack(cfn, stack_name))
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
        )
    except WaiterError as err:
        raise AssertionError(f"{err}; failed resources: {_failed_resources(cfn, stack_name)}") from err
    return stack_name


def _destroy_stack(cfn, stack_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cfn.delete_stack(StackName=stack_name)
        # Bounded by the cleanup budget the runner gives all teardowns together.
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
    except ClientError as exc:
        if not (
            (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
        ):
            raise


def _stack_outputs(cfn, stack_name: str) -> dict:
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; AssertionError if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
