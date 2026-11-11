"""deploy-runtime-endpoint-cfn-behaves."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-runtime-endpoint-cfn-behaves"
GROUP = "deploy"
SERVICES = ["bedrock-agentcore-control", "cloudformation"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_APP_PY = """\
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
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
"""
_CODE_KEY = "app.zip"


def _template(bucket: str, runtime_name: str, endpoint_name: str) -> str:
    log_groups = ("arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:"
                  "log-group:/aws/bedrock-agentcore/runtimes/*")
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow",
                                       "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                                       "Action": "sts:AssumeRole"}],
                    },
                    "Policies": [{"PolicyName": "sim2real-endpoint-exec", "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Action": ["s3:GetObject"],
                             "Resource": {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket}/{_CODE_KEY}"}},
                            {"Effect": "Allow",
                             "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                        "logs:PutLogEvents"],
                             "Resource": [{"Fn::Sub": log_groups}, {"Fn::Sub": f"{log_groups}:*"}]},
                        ],
                    }}],
                },
            },
            "AgentRuntime": {
                "Type": "AWS::BedrockAgentCore::Runtime",
                "Properties": {
                    "AgentRuntimeName": runtime_name,
                    "RoleArn": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
                    "NetworkConfiguration": {"NetworkMode": "PUBLIC"},
                    "AgentRuntimeArtifact": {"CodeConfiguration": {
                        "Code": {"S3": {"Bucket": bucket, "Prefix": _CODE_KEY}},
                        "Runtime": "PYTHON_3_12",
                        "EntryPoint": ["app.py"],
                    }},
                },
            },
            "Endpoint": {
                "Type": "AWS::BedrockAgentCore::RuntimeEndpoint",
                "Properties": {"AgentRuntimeId": {"Ref": "AgentRuntime"}, "Name": endpoint_name},
            },
        },
        "Outputs": {
            "AgentRuntimeId": {"Value": {"Ref": "AgentRuntime"}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["ExecutionRole", "Arn"]}},
            "EndpointArn": {"Value": {"Ref": "Endpoint"}},
            "EndpointId": {"Value": {"Fn::GetAtt": ["Endpoint", "Id"]}},
        },
    })


def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch == "_")


def _poll(probe, predicate, timeout_s=300.0):
    """``probe()`` every 2 s until ``predicate`` holds (the endpoint settles asynchronously)."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() > deadline:
            raise AssertionError(f"not settled within {timeout_s:.0f}s: {last!r}")
        time.sleep(2)


def _code_bucket(ctx, s3, bucket: str) -> None:
    """A tagged bucket holding the runtime's zipped code; emptied and deleted at cleanup."""
    if ctx.region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app.py", _APP_PY)
    s3.put_object(Bucket=bucket, Key=_CODE_KEY, Body=buf.getvalue())


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for obj in paginate(s3, "list_objects_v2", "Contents", Bucket=bucket):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _reap_log_groups(logs, prefix: str, *, reads: int = 3, budget_s: float = 180.0) -> None:
    """Delete every log group under ``prefix`` until ``reads`` consecutive reads find none.

    The runtime creates these groups itself, outside the stack.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=prefix)["logGroups"]
        if groups:
            absent = 0
            for g in groups:
                try:
                    logs.delete_log_group(logGroupName=g["logGroupName"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log groups under {prefix} remain after {budget_s:.0f}s")
            time.sleep(5)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AgentCore Runtime and RuntimeEndpoint read back through AgentCore, then delete.

    The runtime has the templated role, network and code; the listed endpoint reaches READY on it,
    and after the stack delete the endpoint answers its exact NotFound.
    """
    s3 = ctx.client("s3")
    control = ctx.client("bedrock-agentcore-control")
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")
    bucket = ctx.unique_name("sim2real-endpoint-code-").lower()
    _code_bucket(ctx, s3, bucket)
    runtime_name = _alnum_name(ctx, "sim2realCfnEpRuntime")
    endpoint_name = _alnum_name(ctx, "sim2realCfnEndpoint")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-runtimeendpoint-"),
                            _template(bucket, runtime_name, endpoint_name),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    runtime_id = out["AgentRuntimeId"]
    log_prefix = f"/aws/bedrock-agentcore/runtimes/{runtime_id}-"
    ctx.on_cleanup(lambda: _reap_log_groups(logs, log_prefix))

    runtimes = [r["agentRuntimeArn"] for r in paginate(control, "list_agent_runtimes",
                                                       "agentRuntimes")
                if r["agentRuntimeName"] == runtime_name and r["agentRuntimeId"] == runtime_id]
    assert len(runtimes) == 1, f"runtimes named {runtime_name!r} with id {runtime_id!r}: {runtimes!r}"
    runtime = control.get_agent_runtime(agentRuntimeId=runtime_id)
    code = runtime["agentRuntimeArtifact"]["codeConfiguration"]
    got = (runtime["agentRuntimeArn"], runtime["roleArn"],
           runtime["networkConfiguration"]["networkMode"], code["code"]["s3"]["bucket"],
           code["code"]["s3"]["prefix"], code["runtime"], code["entryPoint"])
    want = (runtimes[0], out["RoleArn"], "PUBLIC", bucket, _CODE_KEY, "PYTHON_3_12", ["app.py"])
    assert got == want, f"runtime reads {got!r}, expected {want!r}"

    endpoint = _poll(lambda: control.get_agent_runtime_endpoint(
        agentRuntimeId=runtime_id, endpointName=endpoint_name), lambda r: r["status"] == "READY")
    got = (endpoint["name"], endpoint["agentRuntimeEndpointArn"], endpoint["id"],
           endpoint["agentRuntimeArn"])
    want = (endpoint_name, out["EndpointArn"], out["EndpointId"], runtime["agentRuntimeArn"])
    assert got == want, f"endpoint reads {got!r}, expected {want!r}"
    listed = [e["agentRuntimeEndpointArn"] for e in paginate(
        control, "list_agent_runtime_endpoints", "runtimeEndpoints", agentRuntimeId=runtime_id)
        if e["name"] == endpoint_name]
    assert listed == [out["EndpointArn"]], f"endpoints named {endpoint_name!r}: {listed!r}"

    delete_stack(cfn, stack_id)
    _reap_log_groups(logs, log_prefix)
    refused = ("ResourceNotFoundException", f"Agent endpoint with name {endpoint_name} not found for agent {runtime_id}")
    expect_error(lambda: control.get_agent_runtime_endpoint(
        agentRuntimeId=runtime_id, endpointName=endpoint_name), *refused)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
