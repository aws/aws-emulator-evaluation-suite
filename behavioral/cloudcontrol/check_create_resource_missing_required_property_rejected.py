"""create-resource-missing-required-property-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-resource-missing-required-property-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateResource is rejected with a schema-validation error when DesiredState omits a
    schema-required property (AssumeRolePolicyDocument for AWS::IAM::Role) -- a distinct
    boundary from a generically malformed-JSON DesiredState."""
    cc = ctx.client("cloudcontrol")
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")

    # Negative: valid JSON, but missing the schema-required AssumeRolePolicyDocument.
    # Cloud Control API performs JSON-schema model validation (required-property check)
    # synchronously before enqueuing the request, rejecting it immediately with
    # ValidationException -- distinct from the generic malformed-JSON case.
    bad_state = json.dumps({"RoleName": role_name, "Description": "missing trust policy"})
    code, message = _error(lambda: cc.create_resource(TypeName="AWS::IAM::Role", DesiredState=bad_state))
    assert code == "ValidationException", f"unexpected error code: {code}"
    expected_message = "Model validation failed (#: required key [AssumeRolePolicyDocument] not found)"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no role was created under that name.
    effect_code, effect_message = _error(lambda: iam.get_role(RoleName=role_name))
    assert effect_code == "NoSuchEntity", f"expected no role to exist, got error code: {effect_code}"
    expected_effect_message = f"The role with name {role_name} cannot be found."
    assert effect_message == expected_effect_message, (
        f"expected message {expected_effect_message!r}, got {effect_message!r}"
    )

    # Positive control: the same shape, but with the required property present, succeeds.
    good_state = json.dumps(
        {
            "RoleName": role_name,
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
            "Tags": [{"Key": "sim2real", "Value": CHECK}],
        }
    )
    resp = cc.create_resource(TypeName="AWS::IAM::Role", DesiredState=good_state)
    token = resp["ProgressEvent"]["RequestToken"]
    ctx.on_cleanup(lambda: cc.delete_resource(TypeName="AWS::IAM::Role", Identifier=role_name))
    final = _wait_for_terminal(cc, token)
    assert final["OperationStatus"] == "SUCCESS", f"expected the positive control to succeed, got {final}"
    created_name = iam.get_role(RoleName=role_name)["Role"]["RoleName"]
    assert created_name == role_name, f"expected role {role_name!r} to exist, got {created_name!r}"


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected SUCCESS raises -- an
    over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _wait_for_terminal(cc, token, timeout_s: float = 120.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} did not reach a terminal state in {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
