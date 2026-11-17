"""cfn-iot-authorizer-signing-enabled-missing-token-key-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from behavioral_harness import tags

CHECK = "cfn-iot-authorizer-signing-enabled-missing-token-key-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "iot", "lambda"]

_AUTHORIZER_CODE = (
    "def handler(event, context):\n"
    "    return {\n"
    "        'isAuthenticated': True,\n"
    "        'principalId': 'sim2real-cia-principal',\n"
    "        'policyDocuments': [],\n"
    "        'disconnectAfterInSeconds': 3600,\n"
    "        'refreshAfterInSeconds': 3600,\n"
    "    }\n"
)

_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_TOKEN_KEY_NAME = "X-Custom-Authorizer-Signature"
_SIGNING_KEY_LABEL = "primary"


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _public_key_pem() -> str:
    """A fresh 2048-bit RSA public key in PEM, the shape TokenSigningPublicKeys expects."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _authorizer_template(
    name: str, function_arn: str, *, token_key_name: str | None, public_key_pem: str | None
) -> str:
    props: dict = {
        "AuthorizerName": name,
        "AuthorizerFunctionArn": function_arn,
        "SigningDisabled": False,
    }
    if token_key_name is not None:
        props["TokenKeyName"] = token_key_name
    if public_key_pem is not None:
        props["TokenSigningPublicKeys"] = {_SIGNING_KEY_LABEL: public_key_pem}
    return json.dumps({
        "Resources": {"Authorizer": {"Type": "AWS::IoT::Authorizer", "Properties": props}},
        "Outputs": {"AuthArn": {"Value": {"Fn::GetAtt": ["Authorizer", "Arn"]}}},
    })


def _execution_role(ctx) -> str:
    """A Lambda-trusted role with no attached policy, enough for an authorizer function."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cia-authfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_authorizer_function(ctx, lam, name: str, role_arn: str) -> None:
    """CreateFunction, retrying only while the fresh role is not yet assumable."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            lam.create_function(
                FunctionName=name, Runtime="python3.12", Handler="index.handler",
                Role=role_arn, Code={"ZipFile": _zip_bytes(_AUTHORIZER_CODE)}, Timeout=10,
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] != "InvalidParameterValueException"
                    or "cannot be assumed" not in err.get("Message", "")
                    or time.monotonic() > deadline):
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))


def _wait_terminal(cfn, stack_name: str, ok_statuses, timeout_s: float = 300.0, interval_s: float = 5.0):
    terminal = {
        "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
        "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    }
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        if last["StackStatus"] in ok_statuses or last["StackStatus"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_name} did not reach a terminal state within {timeout_s}s (last={last!r})"
    )


def _delete_stack(cfn, stack_name: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if "does not exist" in str(exc):
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} ended DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} was not deleted within {timeout_s}s")


def _create_failed_reason(cfn, stack_name: str, logical_id: str) -> str:
    for event in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]:
        if event.get("LogicalResourceId") == logical_id and event.get("ResourceStatus") == "CREATE_FAILED":
            return event.get("ResourceStatusReason") or ""
    raise AssertionError(f"no CREATE_FAILED event for {logical_id!r} in stack {stack_name!r}")


def _redact_call_ids(reason: str) -> str:
    """``reason`` with its per-call Request ID and RequestToken values replaced by a
    fixed placeholder, so the rest can be compared exactly across runs."""
    head, _, tail = reason.partition("Request ID: ")
    _, _, tail = tail.partition(")")
    reason = f"{head}Request ID: <redacted>){tail}"
    head, _, tail = reason.partition("RequestToken: ")
    _, _, tail = tail.partition(",")
    return f"{head}RequestToken: <redacted>,{tail}"


def _expect_error(fn, code: str, message: str) -> None:
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN AWS::IoT::Authorizer with SigningDisabled false and no TokenKeyName fails the
    resource with IoT's own token-key-name refusal and creates nothing; adding TokenKeyName
    and TokenSigningPublicKeys to the same template creates the authorizer cleanly.
    """
    role_arn = _execution_role(ctx)
    lam = ctx.client("lambda")
    iot = ctx.client("iot")
    cfn = ctx.client("cloudformation")

    function_name = ctx.unique_name("sim2real-cia-authfn-")
    _create_authorizer_function(ctx, lam, function_name, role_arn)
    function_arn = lam.get_function(FunctionName=function_name)["Configuration"]["FunctionArn"]

    rejected_name = ctx.unique_name("sim2real-cia-auth-")
    rejected_stack = ctx.unique_name("sim2real-cia-stk-")
    cfn.create_stack(
        StackName=rejected_stack,
        TemplateBody=_authorizer_template(
            rejected_name, function_arn, token_key_name=None, public_key_pem=None
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, rejected_stack))
    stack = _wait_terminal(cfn, rejected_stack, {"ROLLBACK_COMPLETE", "CREATE_FAILED"})
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"expected the missing-TokenKeyName create to roll back, got {stack['StackStatus']!r}"
    )

    reason = _redact_call_ids(_create_failed_reason(cfn, rejected_stack, "Authorizer"))
    expected_reason = (
        f'Resource handler returned message: "Invalid request provided: Token key name for '
        f'authorizer {rejected_name} cannot be null (Service: Iot, Status Code: 400, '
        f'Request ID: <redacted>) (SDK Attempt Count: 1)" (RequestToken: <redacted>, '
        f'HandlerErrorCode: InvalidRequest)'
    )
    assert reason == expected_reason, (
        f"expected CREATE_FAILED reason {expected_reason!r}, got {reason!r}"
    )

    resources = cfn.list_stack_resources(StackName=rejected_stack)["StackResourceSummaries"]
    resource_states = [(r["LogicalResourceId"], r["ResourceType"], r["ResourceStatus"]) for r in resources]
    assert resource_states == [("Authorizer", "AWS::IoT::Authorizer", "DELETE_COMPLETE")], (
        f"the rolled-back resource must end DELETE_COMPLETE with nothing else in the stack, "
        f"got {resource_states!r}"
    )

    _NOT_FOUND = ("ResourceNotFoundException", f"Authorizer {rejected_name} not found")
    _expect_error(lambda: iot.describe_authorizer(authorizerName=rejected_name), *_NOT_FOUND)

    # Positive control: the same template, with TokenKeyName and TokenSigningPublicKeys
    # added, creates cleanly.
    control_name = ctx.unique_name("sim2real-cia-auth-")
    control_stack = ctx.unique_name("sim2real-cia-stk-")
    cfn.create_stack(
        StackName=control_stack,
        TemplateBody=_authorizer_template(
            control_name, function_arn,
            token_key_name=_TOKEN_KEY_NAME, public_key_pem=_public_key_pem(),
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, control_stack))
    stack = _wait_terminal(cfn, control_stack, {"CREATE_COMPLETE"})
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the positive control with TokenKeyName and TokenSigningPublicKeys must create "
        f"cleanly, got {stack['StackStatus']!r}"
    )
    description = iot.describe_authorizer(authorizerName=control_name)["authorizerDescription"]
    assert description["tokenKeyName"] == _TOKEN_KEY_NAME, (
        f"expected tokenKeyName {_TOKEN_KEY_NAME!r}, got {description['tokenKeyName']!r}"
    )
    assert set(description["tokenSigningPublicKeys"]) == {_SIGNING_KEY_LABEL}, (
        f"expected one signing key named {_SIGNING_KEY_LABEL!r}, got "
        f"{set(description['tokenSigningPublicKeys'])!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
