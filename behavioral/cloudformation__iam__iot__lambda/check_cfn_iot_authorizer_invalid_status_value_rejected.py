"""cfn-iot-authorizer-invalid-status-value-rejected."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from typing import Any

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from behavioral_harness import tags

CHECK = "cfn-iot-authorizer-invalid-status-value-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "iot", "lambda"]

_HANDLER_SOURCE = (
    "def handler(event, context):\n"
    "    return {\n"
    "        'isAuthenticated': True,\n"
    "        'principalId': 'sim2real-cfn-authorizer',\n"
    "        'disconnectAfterInSeconds': 3600,\n"
    "        'refreshAfterInSeconds': 3600,\n"
    "        'policyDocuments': [],\n"
    "    }\n"
)

_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}

_HANDLER_REASON_PREFIX = 'Resource handler returned message: "'
_HANDLER_REASON_TOKEN_MARKER = '" (RequestToken: '
_HANDLER_REASON_CODE_MARKER = ', HandlerErrorCode: '


def _function_zip(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _signing_public_key_pem() -> str:
    """A fresh RSA public key, PEM-encoded, for the authorizer's token signing config."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _authorizer_template(function_arn: str, *, status: str) -> str:
    """A template with one AWS::IoT::Authorizer, signing disabled, no AuthorizerName."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Authorizer": {
                    "Type": "AWS::IoT::Authorizer",
                    "Properties": {
                        "AuthorizerFunctionArn": function_arn,
                        "SigningDisabled": True,
                        "Status": status,
                    },
                }
            },
            "Outputs": {"AuthorizerRef": {"Value": {"Ref": "Authorizer"}}},
        }
    )


def _execution_role(ctx, iam) -> str:
    """A Lambda-trusted role with no attached policy, enough for an authorizer function."""
    role_name = ctx.unique_name("sim2real-xsvc-cfnauth-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_function(ctx, lam, name: str, role_arn: str) -> str:
    """CreateFunction, retrying while the fresh execution role is still propagating in IAM."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Handler="index.handler",
                Role=role_arn,
                Code={"ZipFile": _function_zip(_HANDLER_SOURCE)},
                Timeout=10,
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if (
                err["Code"] != "InvalidParameterValueException"
                or "cannot be assumed" not in err.get("Message", "")
                or time.monotonic() > deadline
            ):
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    return lam.get_function(FunctionName=name)["Configuration"]["FunctionArn"]


def _await_stack(cfn, stack_name: str, ok_statuses: set[str], *, timeout_s: float = 300.0,
                  interval_s: float = 5.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        if last["StackStatus"] in ok_statuses or last["StackStatus"] in _TERMINAL_STACK_STATUSES:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached {ok_statuses!r}; last seen {last!r}")


def _resource_status_reason(cfn, stack_name: str, logical_id: str, status: str) -> str | None:
    for event in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]:
        if event.get("LogicalResourceId") == logical_id and event.get("ResourceStatus") == status:
            return event.get("ResourceStatusReason")
    return None


def _split_handler_rejection(reason: str | None, *, expected_message: str,
                               expected_handler_code: str) -> None:
    """Assert a CFN "Resource handler returned message" reason, apart from its one-shot
    RequestToken: that token is CFN's own per-attempt id, never the same value twice, so only
    its shape (a UUID) is checked rather than its value.
    """
    assert reason is not None, "expected a CREATE_FAILED event naming a handler rejection"
    assert reason.startswith(_HANDLER_REASON_PREFIX), f"reason has an unexpected shape: {reason!r}"
    body = reason[len(_HANDLER_REASON_PREFIX):]
    assert _HANDLER_REASON_TOKEN_MARKER in body, f"reason has an unexpected shape: {reason!r}"
    message, _, tail = body.partition(_HANDLER_REASON_TOKEN_MARKER)
    assert message == expected_message, f"expected handler message {expected_message!r}, got {message!r}"
    assert _HANDLER_REASON_CODE_MARKER in tail, f"reason has an unexpected shape: {reason!r}"
    token, _, code_part = tail.partition(_HANDLER_REASON_CODE_MARKER)
    assert code_part == f"{expected_handler_code})", (
        f"expected HandlerErrorCode {expected_handler_code!r}, got {code_part!r}"
    )
    uuid.UUID(token)  # raises ValueError if this is not a UUID-shaped request token


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    try:
        prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if "does not exist" in str(exc):
            return
        raise
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_id} entered DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id} was not deleted within {timeout_s}s")


@tags(
    "axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control"
)
def run(ctx) -> None:
    """A CFN AWS::IoT::Authorizer declaring a Status outside ACTIVE/INACTIVE fails to create and
    its stack resource never gets a physical id; the same template with a valid Status succeeds.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    iot = ctx.client("iot")
    cfn = ctx.client("cloudformation")

    function_name = ctx.unique_name("sim2real-xsvc-cfnauth-fn-")
    function_arn = _create_function(ctx, lam, function_name, _execution_role(ctx, iam))

    broken_stack = ctx.unique_name("sim2real-xsvc-cfnauth-stack-")
    cfn.create_stack(
        StackName=broken_stack,
        TemplateBody=_authorizer_template(function_arn, status="ENABLED"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown_stack(cfn, broken_stack))
    stack = _await_stack(cfn, broken_stack, {"ROLLBACK_COMPLETE", "CREATE_FAILED"})
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"expected the invalid-Status create to roll back, got {stack['StackStatus']!r}"
    )
    reason = _resource_status_reason(cfn, broken_stack, "Authorizer", "CREATE_FAILED")
    _split_handler_rejection(
        reason,
        expected_message=(
            "Model validation failed (#/Status: #: only 1 subschema matches out of 2)\n"
            "#/Status: failed validation constraint for keyword [enum] (#/Status)"
        ),
        expected_handler_code="InvalidRequest",
    )
    broken_resources = cfn.list_stack_resources(StackName=broken_stack)["StackResourceSummaries"]
    assert len(broken_resources) == 1 and broken_resources[0]["LogicalResourceId"] == "Authorizer", (
        f"expected exactly the one Authorizer resource entry, got {broken_resources!r}"
    )
    assert "PhysicalResourceId" not in broken_resources[0], (
        "a create IoT itself refused must never have minted a physical authorizer, but "
        f"PhysicalResourceId is present: {broken_resources[0]!r}"
    )
    assert broken_resources[0]["ResourceStatus"] == "DELETE_COMPLETE", (
        f"expected the rolled-back Authorizer entry to read DELETE_COMPLETE, got "
        f"{broken_resources[0]['ResourceStatus']!r}"
    )

    control_stack = ctx.unique_name("sim2real-xsvc-cfnauth-stack-")
    cfn.create_stack(
        StackName=control_stack,
        TemplateBody=_authorizer_template(function_arn, status="ACTIVE"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown_stack(cfn, control_stack))
    control = _await_stack(cfn, control_stack, {"CREATE_COMPLETE"})
    assert control["StackStatus"] == "CREATE_COMPLETE", (
        f"the same template with a valid Status must create cleanly, got {control['StackStatus']!r}"
    )
    control_resources = cfn.list_stack_resources(StackName=control_stack)["StackResourceSummaries"]
    control_name = next(
        r["PhysicalResourceId"] for r in control_resources if r["ResourceType"] == "AWS::IoT::Authorizer"
    )
    described = iot.describe_authorizer(authorizerName=control_name)["authorizerDescription"]
    assert described["status"] == "ACTIVE", f"expected status ACTIVE, got {described['status']!r}"
    assert described["authorizerFunctionArn"] == function_arn, (
        f"expected authorizerFunctionArn {function_arn!r}, got {described['authorizerFunctionArn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
