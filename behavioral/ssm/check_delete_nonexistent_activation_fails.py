"""delete-nonexistent-activation-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-activation-fails"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteActivation removes a real activation from DescribeActivations, while a well-formed but
    never-issued ActivationId fails with InvalidActivation and an empty message."""

    ssm = ctx.client("ssm")
    iam = ctx.client("iam")

    def _error(fn):
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        raise AssertionError(f"expected a ClientError, call unexpectedly succeeded: {result!r}")

    role_name = ctx.unique_name("sim2real-behav-ssm-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ssm.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    activation_id = _create_activation_with_retry(
        ssm, role_name, description=ctx.unique_name("sim2real-behav-probe-activation-")
    )
    ctx.on_cleanup(lambda: _delete_activation_if_present(ssm, activation_id))

    present = [a["ActivationId"] for a in ssm.describe_activations()["ActivationList"]]
    assert activation_id in present, "created activation not visible in DescribeActivations"

    # Positive control: the same call, a real activation id.
    ssm.delete_activation(ActivationId=activation_id)
    present_after = [a["ActivationId"] for a in ssm.describe_activations()["ActivationList"]]
    assert activation_id not in present_after, (
        "DeleteActivation on a real activation did not remove it from DescribeActivations"
    )

    # Negative: a well-formed but never-issued ActivationId.
    code, message = _error(
        lambda: ssm.delete_activation(ActivationId="00000000-0000-0000-0000-000000000000")
    )
    assert code == "InvalidActivation", f"expected InvalidActivation, got {code!r}"
    # AWS answers this refusal with an empty message.
    assert message == "", f"DeleteActivation message: {message!r}"


def _delete_activation_if_present(ssm, activation_id: str) -> None:
    try:
        ssm.delete_activation(ActivationId=activation_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidActivation":
            raise

def _create_activation_with_retry(ssm, role_name: str, description: str, attempts: int = 12) -> str:
    """IAM roles are eventually consistent: a just-created role (and its trust policy)
    may not yet be visible to the SSM control plane, which surfaces as InvalidParameters
    or a ValidationException complaining about a nonexistent role. Retry through both
    until the role has propagated."""
    last_exc = None
    for i in range(attempts):
        try:
            resp = ssm.create_activation(
                IamRole=role_name,
                RegistrationLimit=1,
                Description=description,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            return resp["ActivationId"]
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
