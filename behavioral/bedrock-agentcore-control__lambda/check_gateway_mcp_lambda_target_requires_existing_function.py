"""gateway-mcp-lambda-target-requires-existing-function."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gateway-mcp-lambda-target-requires-existing-function"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control", "lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A gateway MCP target bound to a Lambda function that does not exist never becomes READY,
    and the byte-identical binding converges to READY once that exact function is created."""
    bac = ctx.client("bedrock-agentcore-control")
    lam = ctx.client("lambda")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    gateway_role_arn = _create_gateway_role(ctx)
    gateway_id = _create_ready_gateway(ctx, bac, gateway_role_arn)

    # The function name is chosen now and created LATER, so the same ARN string is first dangling
    # and then valid.
    function_name = _function_name(ctx, "sim2real-bacgw-tool-")
    function_arn = f"arn:aws:lambda:{ctx.region}:{account_id}:function:{function_name}"
    absent_code, absent_message = _error_or_raise(
        lambda: lam.get_function(FunctionName=function_name),
        subject=f"GetFunction({function_name})",
    )
    assert absent_code == "ResourceNotFoundException", (
        f"premise broken: Lambda {function_name!r} does not read as absent, got "
        f"code={absent_code!r}"
    )
    assert absent_message == f"Function not found: {function_arn}", (
        f"premise broken: unexpected GetFunction not-found message {absent_message!r}"
    )

    target_name = _target_name(ctx, "sim2real-lambdatgt-")
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
                                "name": "sim2real_echo",
                                "description": "Echo a string back, for fidelity checking only.",
                                # Lowercase JSON-Schema type names; the uppercase enum form
                                # is refused with ValidationException.
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "message": {
                                            "type": "string",
                                            "description": "The string to echo.",
                                        }
                                    },
                                    "required": ["message"],
                                },
                            }
                        ]
                    },
                }
            }
        },
        # Required even for a Lambda target, and it must carry no iamCredentialProvider payload.
        "credentialProviderConfigurations": [
            {"credentialProviderType": "GATEWAY_IAM_ROLE"}
        ],
    }

    raised = None
    accepted = None
    try:
        # A fresh gateway role is eventually consistent; only that role-flavoured refusal retries.
        accepted = _retry_until_role_usable(lambda: bac.create_gateway_target(**target_kwargs))
    except ClientError as err:
        raised = err.response["Error"]["Code"]
        raised_message = err.response["Error"].get("Message")

    if raised is not None:
        assert raised == "ValidationException", (
            f"expected CreateGatewayTarget to refuse the dangling Lambda ARN {function_arn!r} "
            f"with ValidationException, got {raised!r}"
        )
        expected_message = f"Lambda function not found: {function_arn}. Verify the function ARN is correct and retry."
        assert raised_message == expected_message, f"expected {expected_message!r}, got {raised_message!r}"
        # Effect absent at the consumer, via a different operation than the mutation.
        assert not _target_named(bac, gateway_id, target_name), (
            f"target {target_name!r} is listed on gateway {gateway_id} despite "
            f"CreateGatewayTarget failing with {raised!r}"
        )
    else:
        dangling_id = accepted["targetId"]
        settled = _poll_until(
            lambda: bac.get_gateway_target(
                gatewayIdentifier=gateway_id, targetId=dangling_id
            ),
            lambda t: t["status"] in _TERMINAL,
            "a target bound to a nonexistent Lambda to reach a terminal status",
            timeout_s=240.0,
        )
        assert settled["status"] != "READY", (
            f"a gateway target bound to the nonexistent Lambda {function_arn!r} reached READY: "
            f"statusReasons={settled.get('statusReasons')!r}"
        )
        bac.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=dangling_id)
        gone_code, gone_message = _error_or_raise(
            lambda: bac.get_gateway_target(gatewayIdentifier=gateway_id, targetId=dangling_id),
            subject="the rejected target to disappear before the positive control reuses its name",
            timeout_s=180.0,
        )
        assert gone_code == "ResourceNotFoundException", gone_code
        assert gone_message == (
            "Failed to retrieve target because it doesn't exist. Retry the request with a "
            "different resource identifier."
        ), gone_message

    # Restore exactly one thing: create the Lambda the target names.
    _create_tool_function(ctx, lam, function_name)
    live = lam.get_function(FunctionName=function_name)
    assert live["Configuration"]["FunctionArn"] == function_arn, (
        f"expected the created Lambda's ARN to be exactly the one the refused target named: "
        f"expected {function_arn!r}, got {live['Configuration']['FunctionArn']!r}"
    )

    # Positive control: the byte-identical CreateGatewayTarget must now converge.
    positive = bac.create_gateway_target(**target_kwargs)
    positive_id = positive["targetId"]
    final = _poll_until(
        lambda: bac.get_gateway_target(gatewayIdentifier=gateway_id, targetId=positive_id),
        lambda t: t["status"] in _TERMINAL,
        "the identical target to settle once its Lambda exists",
        timeout_s=240.0,
    )
    assert final["status"] == "READY", (
        f"the positive control did not converge: status={final['status']!r} "
        f"statusReasons={final.get('statusReasons')!r} lambdaArn={function_arn!r}"
    )

    # Terminal read at the CONSUMER (the gateway), through a different operation than the
    # mutation: the binding is visible in the gateway's target list and reports the exact ARN.
    assert _target_named(bac, gateway_id, target_name), (
        f"target {target_name!r} reached READY but is not listed on gateway {gateway_id}"
    )
    bound_arn = final["targetConfiguration"]["mcp"]["lambda"]["lambdaArn"]
    assert bound_arn == function_arn, (
        f"expected the gateway target to report lambdaArn {function_arn!r}, got {bound_arn!r}"
    )
    tools = final["targetConfiguration"]["mcp"]["lambda"]["toolSchema"]["inlinePayload"]
    tool_names = [t["name"] for t in tools]
    assert tool_names == ["sim2real_echo"], (
        f"expected the gateway target to report exactly ['sim2real_echo'], got {tool_names!r}"
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
            lambda target_id=target_id: control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)["status"],
            lambda target_id=target_id: control.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
            what=f"gateway target {target_id}",
        )
    _ac_delete_and_wait(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id)["status"],
        lambda: control.delete_gateway(gatewayIdentifier=gateway_id),
        what=f"gateway {gateway_id}",
    )


_TERMINAL = (
    "READY",
    "FAILED",
    "UPDATE_UNSUCCESSFUL",
    "SYNCHRONIZE_UNSUCCESSFUL",
)


def _poll_until(probe, predicate, reason, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {reason}; last value={last!r}")


def _error_or_raise(fn, subject, timeout_s=0.0, interval_s=2.0):
    """Call fn() until it is refused; return the refusal's (code, message). A call that still
    succeeds once timeout_s has passed RAISES rather than returning a falsy sentinel."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"{subject} unexpectedly SUCCEEDED; expected it to be refused")
        time.sleep(interval_s)


def _create_tool_function(ctx, lam, function_name):
    role_arn = _create_lambda_role(ctx)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "index.py",
            "def handler(event, context):\n"
            "    return {'message': event.get('message', '')}\n",
        )
    created = _retry_until_role_usable(
        lambda: lam.create_function(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": buf.getvalue()},
            Timeout=10,
            Tags={"sim2real": CHECK},
        )
    )
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: lam.delete_function(FunctionName=function_name))
    )
    assert created["FunctionName"] == function_name, (
        f"expected to create Lambda {function_name!r}, got {created['FunctionName']!r}"
    )
    lam.get_waiter("function_active_v2").wait(
        FunctionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-bacgw-lambda-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        )
    )
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _create_ready_gateway(ctx, bac, role_arn):
    gateway_name = _gateway_name(ctx, "sim2real-gw-lambdatgt-")
    gw = _retry_until_role_usable(
        lambda: bac.create_gateway(
            name=gateway_name,
            roleArn=role_arn,
            authorizerType="AWS_IAM",
            tags={"sim2real": CHECK},
        )
    )
    gateway_id = gw["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(bac, gateway_id))
    settled = _poll_until(
        lambda: bac.get_gateway(gatewayIdentifier=gateway_id),
        lambda g: g["status"] in ("READY", "FAILED"),
        "the gateway to reach a terminal create status",
        timeout_s=240.0,
    )
    assert settled["status"] == "READY", (
        f"gateway {gateway_id} did not become READY: status={settled['status']!r} "
        f"statusReasons={settled.get('statusReasons')!r}"
    )
    return gateway_id


def _target_named(bac, gateway_id, target_name):
    next_token = None
    while True:
        kwargs = {"gatewayIdentifier": gateway_id}
        if next_token:
            kwargs["nextToken"] = next_token
        page = bac.list_gateway_targets(**kwargs)
        for item in page["items"]:
            if item["name"] == target_name:
                return True
        next_token = page.get("nextToken")
        if not next_token:
            return False


def _gateway_name(ctx, prefix):
    raw = ctx.unique_name(prefix)
    return "".join(c for c in raw if c.isalnum() or c == "-")[:48].rstrip("-")


def _target_name(ctx, prefix):
    raw = ctx.unique_name(prefix)
    return "".join(c for c in raw if c.isalnum() or c in "-_")[:48]


def _function_name(ctx, prefix):
    """Lambda function names allow [a-zA-Z0-9-_], max 64."""
    raw = ctx.unique_name(prefix)
    return "".join(c for c in raw if c.isalnum() or c in "-_")[:60]


def _create_gateway_role(ctx):
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-bac-lambdatgt-")[:64]
    trust_policy = {
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        )
    )
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _retry_until_role_usable(fn, timeout_s=120.0, interval_s=6.0):
    """A freshly created role is eventually consistent; both Lambda and AgentCore report that as
    a role-flavoured rejection. Retry only those."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code in (
                "AccessDeniedException",
                "ValidationException",
                "InvalidParameterValueException",
            ) and "role" in message.lower():
                last = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"role never became usable within {timeout_s}s; last error={last}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "NoSuchEntity",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
