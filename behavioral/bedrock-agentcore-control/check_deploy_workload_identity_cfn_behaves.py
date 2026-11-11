"""deploy-workload-identity-cfn-behaves."""
from __future__ import annotations

import io
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-workload-identity-cfn-behaves"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]

_APP_PY = """\
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"healthy" if self.path == "/ping" else b"")

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
"""

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  ExplicitWorkloadIdentity:
    Type: AWS::BedrockAgentCore::WorkloadIdentity
    Properties:
      Name: '__WORKLOAD_IDENTITY_NAME__'
      Tags:
        - Key: sim2real:managed
          Value: 'true'
        - Key: sim2real:prefix
          Value: sim2real-wi
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
        - PolicyName: sim2real-wi-runtime-exec
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
  DependentAgentRuntime:
    Type: AWS::BedrockAgentCore::Runtime
    Properties:
      AgentRuntimeName: '__RUNTIME_NAME__'
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
      Tags:
        sim2real:managed: 'true'
        sim2real:prefix: sim2real-wi
Outputs:
  WorkloadIdentityName:
    Value: !Ref ExplicitWorkloadIdentity
  WorkloadIdentityArn:
    Value: !GetAtt ExplicitWorkloadIdentity.WorkloadIdentityArn
  AgentRuntimeId:
    Value: !Ref DependentAgentRuntime
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CloudFormation-deployed WorkloadIdentity coexists with a live dependent AgentRuntime."""
    control = ctx.client("bedrock-agentcore-control")
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-wi-code-").lower()
    _create_bucket(ctx, s3, bucket_name)
    code_key = "app.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app.py", _APP_PY)
    s3.put_object(Bucket=bucket_name, Key=code_key, Body=buf.getvalue())

    wi_name = ctx.unique_name("sim2real-wi-")
    runtime_name = _alnum_name(ctx, "sim2realWiRuntime")
    template_body = (
        _TEMPLATE.replace("__WORKLOAD_IDENTITY_NAME__", wi_name)
        .replace("__RUNTIME_NAME__", runtime_name)
        .replace("__CODE_OBJECT_ARN__", f"arn:aws:s3:::{bucket_name}/{code_key}")
        .replace("__CODE_BUCKET__", bucket_name)
        .replace("__CODE_KEY__", code_key)
    )

    stack_name = _deploy_cfn(ctx, cfn, template_body)
    outputs = _stack_outputs(cfn, stack_name)
    wi_name_out = outputs["WorkloadIdentityName"]
    wi_arn = outputs["WorkloadIdentityArn"]
    runtime_id = outputs["AgentRuntimeId"]

    got_wi = control.get_workload_identity(name=wi_name_out)
    assert got_wi["workloadIdentityArn"] == wi_arn, (
        f"expected GetWorkloadIdentity to echo the CFN-stack ARN {wi_arn!r}, got {got_wi['workloadIdentityArn']!r}"
    )

    ready_runtime = _poll_until(
        lambda: control.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r["status"] == "READY",
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert ready_runtime["agentRuntimeName"] == runtime_name, (
        f"expected READY runtime name {runtime_name!r}, got {ready_runtime['agentRuntimeName']!r}"
    )

    still_there = control.get_workload_identity(name=wi_name_out)
    assert still_there["workloadIdentityArn"] == wi_arn, (
        f"expected WorkloadIdentity {wi_name_out!r} to still report ARN {wi_arn!r} "
        f"while its stack sibling AgentRuntime is READY, got {still_there['workloadIdentityArn']!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )

    runtime_code, runtime_message = _error(lambda: control.get_agent_runtime(agentRuntimeId=runtime_id))
    assert runtime_code == "ResourceNotFoundException", (
        f"expected GetAgentRuntime on the deleted stack's runtime {runtime_id!r} to raise "
        f"ResourceNotFoundException, got {runtime_code!r}"
    )
    expected_runtime = (
        f"Agent with agentId: {runtime_id}, accountId: {ctx.account}, and version: null not found!"
    )
    assert runtime_message == expected_runtime, (
        f"expected message {expected_runtime!r}, got {runtime_message!r}"
    )
    wi_code, wi_message = _error(lambda: control.get_workload_identity(name=wi_name_out))
    assert wi_code == "ResourceNotFoundException", (
        f"expected GetWorkloadIdentity on the deleted stack's identity {wi_name_out!r} to raise "
        f"ResourceNotFoundException, got {wi_code!r}"
    )
    expected_wi = f"WorkloadIdentity with id {wi_name_out} not found."
    assert wi_message == expected_wi, f"expected message {expected_wi!r}, got {wi_message!r}"


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
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-wi"}]},
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


def _deploy_cfn(ctx, cfn, template_body: str) -> str:
    stack_name = ctx.unique_name("sim2real-workloadidentity-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-wi"},
        ],
    )
    ctx.on_cleanup(lambda: _destroy_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )
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
