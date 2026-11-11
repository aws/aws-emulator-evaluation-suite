"""activation-list-and-describe-status."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activation-list-and-describe-status"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Created activations appear in DescribeActivations with correct
    registration-limit and status fields."""
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-act-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ssm.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    activation = _create_activation_with_retry(
        ssm, role_name, description=ctx.unique_name("sim2real-activation-desc-")
    )
    activation_id = activation["ActivationId"]
    ctx.on_cleanup(lambda: _delete_activation_if_exists(ssm, activation_id))

    found = _find_activation(ssm, activation_id)
    assert found is not None, "created activation not visible in DescribeActivations"
    assert found["IamRole"] == role_name, f"expected IamRole {role_name!r}, got {found['IamRole']!r}"
    assert found["RegistrationLimit"] == 5, f"expected RegistrationLimit 5, got {found['RegistrationLimit']!r}"
    assert found["RegistrationsCount"] == 0, f"expected RegistrationsCount 0, got {found['RegistrationsCount']!r}"

    ssm.delete_activation(ActivationId=activation_id)
    found = _find_activation(ssm, activation_id)
    assert found is None, "deleted activation still visible in DescribeActivations"

    dup_delete_code, dup_delete_message = _error_code(
        lambda: ssm.delete_activation(ActivationId=activation_id)
    )
    assert dup_delete_code == "InvalidActivation", (
        f"expected InvalidActivation deleting an already-deleted activation, got {dup_delete_code!r}"
    )
    # AWS sends this refusal with an empty message.
    assert dup_delete_message == "", f"expected an empty message, got {dup_delete_message!r}"


def _error_code(fn):
    """Runs fn and returns its ClientError (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _create_activation_with_retry(ssm, role_name: str, description: str, attempts: int = 12):
    """IAM roles are eventually consistent: a just-created role (and its trust
    policy) may not yet be visible to the SSM control plane, which surfaces as
    either InvalidParameters or a ValidationException complaining about a
    "Nonexistent role or missing ssm service principal". Retry through both
    until the role has propagated."""
    last_exc = None
    for i in range(attempts):
        try:
            return ssm.create_activation(
                IamRole=role_name,
                RegistrationLimit=5,
                Description=description,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            transient = code == "InvalidParameters" or (
                code == "ValidationException"
                and ("role" in message.lower() or "trust" in message.lower())
            )
            if not transient or i == attempts - 1:
                raise
            last_exc = exc
            time.sleep(3.0)
    raise last_exc


def _find_activation(ssm, activation_id: str):
    next_token = None
    for _ in range(50):
        kwargs = {"NextToken": next_token} if next_token else {}
        page = ssm.describe_activations(**kwargs)
        for item in page.get("ActivationList", []):
            if item["ActivationId"] == activation_id:
                return item
        next_token = page.get("NextToken")
        if not next_token:
            break
    return None


def _delete_activation_if_exists(ssm, activation_id: str) -> None:
    try:
        ssm.delete_activation(ActivationId=activation_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidActivationId", "InvalidActivation"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
