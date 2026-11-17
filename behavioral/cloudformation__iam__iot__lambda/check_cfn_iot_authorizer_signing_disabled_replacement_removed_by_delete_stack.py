"""cfn-iot-authorizer-signing-disabled-replacement-removed-by-delete-stack."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from behavioral_harness import tags

CHECK = "cfn-iot-authorizer-signing-disabled-replacement-removed-by-delete-stack"
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


def _authorizer_template(
    function_arn: str, *, signing_disabled: bool, token_key_name: str, public_key_label: str,
    public_key_pem: str,
) -> str:
    """A template with one AWS::IoT::Authorizer, no AuthorizerName so CFN mints one.

    IoT refuses a non-null token signing key map once signing is disabled, so the keys are
    declared only while ``signing_disabled`` is False.
    """
    properties: dict[str, Any] = {
        "AuthorizerFunctionArn": function_arn,
        "SigningDisabled": signing_disabled,
        "Status": "ACTIVE",
    }
    if not signing_disabled:
        properties["TokenKeyName"] = token_key_name
        properties["TokenSigningPublicKeys"] = {public_key_label: public_key_pem}
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"Authorizer": {"Type": "AWS::IoT::Authorizer", "Properties": properties}},
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


def _stack_outputs(stack: dict[str, Any]) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


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


def _authorizer_physical_name(cfn, stack_name: str) -> str:
    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    matches = [r for r in resources if r["ResourceType"] == "AWS::IoT::Authorizer"]
    assert len(matches) == 1, f"expected exactly one AWS::IoT::Authorizer resource, found {matches!r}"
    return matches[0]["PhysicalResourceId"]


def _delete_stack_and_await(cfn, stack_name: str, *, timeout_s: float = 300.0,
                             interval_s: float = 5.0) -> None:
    cfn.delete_stack(StackName=stack_name)
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
            raise AssertionError(f"stack {stack_name} entered DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} was not deleted within {timeout_s}s")


def _expect_error(fn, expected_code: str, expected_message: str) -> None:
    """Assert ``fn()`` is refused with exactly ``(expected_code, expected_message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))
        assert got == (expected_code, expected_message), (
            f"expected refusal {(expected_code, expected_message)!r}, got {got!r}"
        )
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control"
)
def run(ctx) -> None:
    """Flipping SigningDisabled on a nameless AWS::IoT::Authorizer replaces it under a new
    generated name, and deleting the stack afterward removes that replacement, leaving no
    authorizer under the displaced original's name or the replacement's name.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    iot = ctx.client("iot")
    cfn = ctx.client("cloudformation")

    function_name = ctx.unique_name("sim2real-xsvc-cfnauth-fn-")
    function_arn = _create_function(ctx, lam, function_name, _execution_role(ctx, iam))

    token_key_name = ctx.unique_name("sim2real-xsvc-cfnauth-tk-")
    public_key_label = ctx.unique_name("sim2real-xsvc-cfnauth-key-")
    public_key_pem = _signing_public_key_pem()

    stack_name = ctx.unique_name("sim2real-xsvc-cfnauth-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_authorizer_template(
            function_arn, signing_disabled=False, token_key_name=token_key_name,
            public_key_label=public_key_label, public_key_pem=public_key_pem,
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_await(cfn, stack_name))
    created = _await_stack(cfn, stack_name, {"CREATE_COMPLETE"})
    assert created["StackStatus"] == "CREATE_COMPLETE", f"create ended in {created['StackStatus']!r}"

    original_name = _authorizer_physical_name(cfn, stack_name)
    assert _stack_outputs(created)["AuthorizerRef"] == original_name, (
        "Ref must return the same name as the resource's PhysicalResourceId"
    )
    original = iot.describe_authorizer(authorizerName=original_name)["authorizerDescription"]
    assert original["signingDisabled"] is False, (
        f"expected the original authorizer's signingDisabled False, got {original['signingDisabled']!r}"
    )
    assert original["status"] == "ACTIVE", f"expected status ACTIVE, got {original['status']!r}"
    assert original["authorizerFunctionArn"] == function_arn, (
        f"expected authorizerFunctionArn {function_arn!r}, got {original['authorizerFunctionArn']!r}"
    )

    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=_authorizer_template(
            function_arn, signing_disabled=True, token_key_name=token_key_name,
            public_key_label=public_key_label, public_key_pem=public_key_pem,
        ),
    )
    updated = _await_stack(cfn, stack_name, {"UPDATE_COMPLETE"})
    assert updated["StackStatus"] == "UPDATE_COMPLETE", f"update ended in {updated['StackStatus']!r}"

    replacement_name = _authorizer_physical_name(cfn, stack_name)
    assert replacement_name != original_name, (
        "the SigningDisabled flip must replace the authorizer under a newly generated name, "
        f"but the physical name stayed {original_name!r}"
    )
    replacement = iot.describe_authorizer(authorizerName=replacement_name)["authorizerDescription"]
    assert replacement["signingDisabled"] is True, (
        f"expected the replacement authorizer's signingDisabled True, got {replacement['signingDisabled']!r}"
    )
    assert replacement["authorizerFunctionArn"] == function_arn, (
        f"expected authorizerFunctionArn {function_arn!r}, got {replacement['authorizerFunctionArn']!r}"
    )

    _original_not_found = ("ResourceNotFoundException", f"Authorizer {original_name} not found")
    _expect_error(lambda: iot.describe_authorizer(authorizerName=original_name), *_original_not_found)

    _delete_stack_and_await(cfn, stack_name)

    _replacement_not_found = (
        "ResourceNotFoundException", f"Authorizer {replacement_name} not found"
    )
    _expect_error(
        lambda: iot.describe_authorizer(authorizerName=replacement_name), *_replacement_not_found
    )
    _expect_error(
        lambda: iot.describe_authorizer(authorizerName=original_name), *_original_not_found
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
