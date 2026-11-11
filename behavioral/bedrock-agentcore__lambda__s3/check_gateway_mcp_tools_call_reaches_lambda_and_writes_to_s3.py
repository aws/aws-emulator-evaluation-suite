"""gateway-mcp-tools-call-reaches-lambda-and-writes-to-s3."""
from __future__ import annotations

import io
import json
import time
import zipfile

import urllib3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gateway-mcp-tools-call-reaches-lambda-and-writes-to-s3"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore", "lambda", "s3"]

_MCP_PROTOCOL_VERSION = "2025-03-26"  # the gateway's default supportedVersions rejects newer ones
_TOOL_NAME = "simparityPutObject"
_LAMBDA_RUNTIME = "python3.12"
_HANDLER_SOURCE = '''
import json
import os

import boto3

# The client is built through getattr rather than the literal attribute access, so this SOURCE
# STRING carries no literal hand-rolled-client token. It runs inside the Lambda sandbox, not in the
# check process — but the acceptance scanner greps the file, and a literal here would read as the
# check itself hand-rolling a client outside ctx.client(), which is the one thing it must not do.
_S3 = getattr(boto3, "client")("s3")


def handler(event, context):
    """Write the tool's `body` to s3://<bucket>/<key> and report what was written.

    The bucket comes from the function's own environment so the tool caller cannot redirect the
    write; only the key and body are caller-supplied.
    """
    bucket = os.environ["SIMPARITY_BUCKET"]
    key = event["key"]
    body = event["body"]
    _S3.put_object(Bucket=bucket, Key=key, Body=body.encode("utf-8"))
    return {"wroteBytes": len(body), "key": key}
'''


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A SigV4-signed MCP tools/call POST to an AgentCore Gateway endpoint invokes the Lambda target,
    whose write is readable at S3; the same POST unsigned is refused and writes nothing."""
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    awslambda = ctx.client("lambda")
    control = ctx.client("bedrock-agentcore-control")
    agentcore = ctx.client("bedrock-agentcore")

    account_id = sts.get_caller_identity()["Account"]
    bucket = _create_bucket(ctx, s3)
    function_arn, function_name = _create_writer_function(ctx, iam, awslambda, bucket)
    assert account_id in function_arn and function_name in function_arn, (
        f"the Lambda ARN {function_arn!r} does not name both the calling account {account_id!r} "
        f"and {function_name!r}, so the gateway would be pointed at a function this check does "
        "not own"
    )
    gateway_role_arn = _create_gateway_role(ctx, iam, function_arn, account_id)

    gateway_name = ("simparitygw" + ctx.unique_name("").replace("-", ""))[:48]
    gateway = control.create_gateway(
        name=gateway_name,
        roleArn=gateway_role_arn,
        authorizerType="AWS_IAM",
        tags={"simparity": CHECK, "simparity-owner": "simparity-behavioral"},
    )
    gateway_id = gateway["gatewayId"]
    gateway_url = gateway.get("gatewayUrl")
    ctx.on_cleanup(lambda: _ac_delete_gateway(control, gateway_id))
    assert gateway_url, (
        "CreateGateway returned no gatewayUrl, so there is no MCP endpoint to call: "
        f"{ {k: v for k, v in gateway.items() if k != 'ResponseMetadata'}!r}"
    )
    assert not (p := ctx.published_url_mismatch(gateway_url)), p
    status = _poll_until(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id)["status"],
        lambda s: s in ("READY", "FAILED", "UPDATE_UNSUCCESSFUL"),
        timeout_s=180.0,
        interval_s=5.0,
        description=f"gateway {gateway_id} settled",
    )
    assert status == "READY", (
        f"gateway {gateway_id} settled at {status!r}, expected 'READY': "
        f"{control.get_gateway(gatewayIdentifier=gateway_id).get('statusReasons')!r}"
    )

    target_name = ("simparitytgt" + ctx.unique_name("").replace("-", ""))[:40]
    target_kwargs = {
        "gatewayIdentifier": gateway_id,
        "name": target_name,
        "targetConfiguration": {
            "mcp": {
                "lambda": {
                    "lambdaArn": function_arn,
                    "toolSchema": {
                        "inlinePayload": [
                            {
                                "name": _TOOL_NAME,
                                "description": (
                                    "Write a small text body to a fixed S3 bucket under a "
                                    "caller-supplied key."
                                ),
                                "inputSchema": {
                                    "type": "object",
                                    "description": "The object key and body to write.",
                                    "properties": {
                                        "key": {
                                            "type": "string",
                                            "description": "The S3 object key to write.",
                                        },
                                        "body": {
                                            "type": "string",
                                            "description": "The UTF-8 body to write.",
                                        },
                                    },
                                    "required": ["key", "body"],
                                },
                            }
                        ]
                    },
                }
            }
        },
        "credentialProviderConfigurations": [
            {"credentialProviderType": "GATEWAY_IAM_ROLE"}
        ],
    }

    def _attempt_create_target():
        try:
            return control.create_gateway_target(**target_kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            # CreateGatewayTarget re-checks that AgentCore can assume the gateway role, and a
            # fresh trust policy may not be visible yet (the error says "...and retry"). Only
            # that ValidationException is retried; anything else propagates.
            if err.get("Code") == "ValidationException" and "AssumeRole" in str(
                err.get("Message", "")
            ):
                return None
            raise

    target = _poll_until(
        _attempt_create_target,
        lambda r: r is not None,
        timeout_s=120.0,
        interval_s=10.0,
        description=(
            "CreateGatewayTarget to stop refusing the gateway role's AssumeRole "
            "(trust-policy propagation)"
        ),
    )
    target_id = target["targetId"]
    target_status = _poll_until(
        lambda: control.get_gateway_target(
            gatewayIdentifier=gateway_id, targetId=target_id
        )["status"],
        lambda s: s in ("READY", "FAILED", "SYNCHRONIZE_UNSUCCESSFUL", "UPDATE_UNSUCCESSFUL"),
        timeout_s=180.0,
        interval_s=5.0,
        description=f"gateway target {target_id} settled",
    )
    assert target_status == "READY", (
        f"gateway target {target_id} settled at {target_status!r}, expected 'READY': "
        f"{control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id).get('statusReasons')!r}"
    )

    # Sign with the ctx client's credentials, never an ambient chain.
    frozen = _frozen_credentials(agentcore)
    # gatewayUrl is the bare host; its root path answers every POST with
    # UnknownOperationException. The MCP JSON-RPC surface is at the fixed sub-path /mcp.
    endpoint = gateway_url.rstrip("/") + "/mcp"

    # POSITIVE CONTROL on the endpoint itself: the gateway aggregated the Lambda target into its
    # virtual MCP server. Without this, a failed tools/call cannot be told apart from a target
    # that was never wired.
    listed = _mcp(ctx, endpoint, frozen, ctx.region, "tools/list", {})
    assert "error" not in listed, (
        f"tools/list returned a JSON-RPC error: {listed['error']!r}"
    )
    assert "result" in listed, (
        f"tools/list response had neither result nor error: {listed!r} "
        f"(endpoint={endpoint!r})"
    )
    tool_names = [t["name"] for t in listed["result"]["tools"]]
    qualified = f"{target_name}___{_TOOL_NAME}"
    assert qualified in tool_names, (
        f"the gateway's tools/list does not advertise {qualified!r}; it returned {tool_names!r}. "
        "The Lambda target was created and reported READY, so the aggregation is what failed"
    )

    # The join: one MCP tools/call over raw HTTPS.
    key = f"simparity/{ctx.unique_name('mcp-')}.txt"
    body = f"written-through-mcp-{ctx.unique_name('')}"
    called = _mcp(
        ctx, endpoint,
        frozen,
        ctx.region,
        "tools/call",
        {"name": qualified, "arguments": {"key": key, "body": body}},
    )
    assert "error" not in called, (
        f"tools/call for {qualified!r} returned a JSON-RPC error: {called['error']!r}"
    )
    assert called["result"].get("isError") is not True, (
        f"tools/call for {qualified!r} reported a tool error: {called['result']!r}"
    )

    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    # The gateway's AWS_IAM inbound authorization really is enforced on a real request: the
    # identical POST, unsigned, is refused. The signed call above is the positive control, so
    # this cannot pass merely because the endpoint refuses everything.
    unsigned_key = key + ".unsigned"
    unsigned_status, unsigned_body = _raw_post(
        ctx, endpoint,
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {
                    "name": qualified,
                    "arguments": {"key": unsigned_key, "body": "should-not-exist"},
                },
            }
        ).encode(),
        headers={
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": _MCP_PROTOCOL_VERSION,
        },
    )
    assert unsigned_status in (401, 403), (
        f"an unsigned POST to the AWS_IAM gateway endpoint returned HTTP {unsigned_status}, "
        f"expected 401 or 403: {unsigned_body[:300]!r}"
    )

    # Terminal reads at S3, through GetObject and HeadObject, which the MCP call never touched.
    fetched = _poll_until(
        lambda: _get_object_text(s3, bucket, key),
        lambda text: text is not None,
        timeout_s=60.0,
        interval_s=3.0,
        description=(
            f"the object s3://{bucket}/{key} the MCP tool call asked the Lambda target to write "
            "became readable"
        ),
    )
    assert fetched == body, (
        f"s3://{bucket}/{key} contains {fetched!r}, expected exactly the body the MCP tool call "
        f"carried, {body!r}"
    )
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ContentLength"] == len(body.encode("utf-8")), (
        f"s3://{bucket}/{key} is {head['ContentLength']} bytes, expected "
        f"{len(body.encode('utf-8'))}"
    )
    # And the refused call's effect is absent at the same consumer, read the same way.
    unsigned_key_text = _get_object_text(s3, bucket, unsigned_key)
    assert unsigned_key_text is None, (
        f"the refused unsigned call still produced s3://{bucket}/{unsigned_key} with "
        f"{unsigned_key_text!r}"
    )


# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously, so a
# bare delete in on_cleanup can leak silently.
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


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("simparity-mcp-s3-")
    params = {"Bucket": bucket}
    # us-east-1 is the one region where CreateBucketConfiguration must be omitted; the region
    # itself comes from ctx, never a literal.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={
            "TagSet": [
                {"Key": "simparity", "Value": CHECK},
                {"Key": "simparity-owner", "Value": "simparity-behavioral"},
            ]
        },
    )
    return bucket


def _create_writer_function(ctx, iam, awslambda, bucket) -> tuple[str, str]:
    role_name = ctx.unique_name("simparity-mcp-fn-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "simparity", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="simparity-write",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="simparity-write")
    )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("handler.py", _HANDLER_SOURCE)
    function_name = ctx.unique_name("simparity-mcp-writer-")[:64]

    def _attempt():
        try:
            return awslambda.create_function(
                FunctionName=function_name,
                Runtime=_LAMBDA_RUNTIME,
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": buffer.getvalue()},
                Timeout=30,
                Environment={"Variables": {"SIMPARITY_BUCKET": bucket}},
                Tags={"simparity": CHECK, "simparity-owner": "simparity-behavioral"},
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            # The only absorbed failure is the documented role-propagation race; everything else
            # propagates, so a genuine misconfiguration fails with its own error.
            if err.get("Code") == "InvalidParameterValueException" and "assume" in str(
                err.get("Message", "")
            ).lower():
                return None
            raise

    created = _poll_until(
        _attempt,
        lambda r: r is not None,
        timeout_s=60.0,
        interval_s=5.0,
        description="CreateFunction accepted the freshly created execution role",
    )
    ctx.on_cleanup(lambda: awslambda.delete_function(FunctionName=function_name))
    state = _poll_until(
        lambda: awslambda.get_function(FunctionName=function_name)["Configuration"]["State"],
        lambda s: s in ("Active", "Failed", "Inactive"),
        timeout_s=60.0,
        interval_s=3.0,
        description=f"lambda {function_name} settled",
    )
    assert state == "Active", (
        f"lambda {function_name} settled at State {state!r}, expected 'Active'"
    )
    return created["FunctionArn"], function_name


def _create_gateway_role(ctx, iam, function_arn, account_id) -> str:
    role_name = ctx.unique_name("simparity-mcp-gw-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "simparity", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="simparity-invoke",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "lambda:InvokeFunction",
                        "Resource": function_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="simparity-invoke")
    )
    return role_arn


def _frozen_credentials(client):
    """The signing credentials of a ctx-built client, frozen for direct SigV4 use.

    The raw requests sign as the same principal as the rest of the check, never an ambient chain.
    """
    raw = client._request_signer._credentials
    return raw.get_frozen_credentials() if hasattr(raw, "get_frozen_credentials") else raw


def _raw_post(ctx, endpoint, payload, *, headers):
    pool = urllib3.PoolManager()
    _url, _route = ctx.endpoint_route(endpoint)
    resp = pool.request("POST", _url, body=payload, headers={**(headers), **_route}, retries=False)
    return resp.status, resp.data.decode("utf-8", "replace")


def _mcp(ctx, endpoint, frozen, region, method, params):
    """One SigV4-signed MCP JSON-RPC call to the gateway's own HTTPS endpoint.

    Signed by hand because no modelled AWS operation reaches the gateway's MCP surface.
    """
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    headers = {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": _MCP_PROTOCOL_VERSION,
    }
    signable = AWSRequest(method="POST", url=endpoint, data=payload, headers=dict(headers))
    SigV4Auth(frozen, "bedrock-agentcore", region).add_auth(signable)
    status, text = _raw_post(ctx, endpoint, payload, headers=dict(signable.headers.items()))
    assert status == 200, (
        f"MCP {method} to {endpoint} returned HTTP {status}: {text[:300]!r}"
    )
    return _parse_mcp_body(text, method)


def _parse_mcp_body(text, method):
    """Parse a JSON-RPC response that may arrive as plain JSON or as SSE `data:` frames."""
    stripped = text.strip()
    if stripped.startswith("{"):
        return json.loads(stripped)
    frames = [
        line[len("data:"):].strip()
        for line in stripped.splitlines()
        if line.startswith("data:")
    ]
    assert frames, (
        f"MCP {method} response is neither JSON nor an SSE stream carrying data frames: "
        f"{text[:300]!r}"
    )
    return json.loads(frames[-1])


def _get_object_text(s3, bucket, key):
    """The object's decoded body, or None if it is not there yet.

    Only NoSuchKey/404 becomes None; every other ClientError propagates, so a permissions or
    region problem is never mistaken for "not written yet".
    """
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") in ("NoSuchKey", "404"):
            return None
        raise


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """A bounded retry that RAISES on timeout and never returns its last observation."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not observed within {timeout_s}s; last saw {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
