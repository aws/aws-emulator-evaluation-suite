"""activation-create-describe-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activation-create-describe-delete"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateActivation is listed by DescribeActivations and gone after DeleteActivation."""

    ssm = ctx.client("ssm")
    iam = ctx.client("iam")

    def _error_code(fn):
        """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

    def _call_with_retry(fn, retries=10, delay=3.0):
        last = None
        for _ in range(retries):
            try:
                return fn()
            except ClientError as exc:
                last = exc
                code = exc.response.get("Error", {}).get("Code")
                # IAM role trust-policy propagation to the SSM control plane is eventually
                # consistent and surfaces as either code.
                if code in ("ValidationException", "TooManyUpdates", "ThrottlingException", "InvalidParameters"):
                    time.sleep(delay)
                    continue
                raise
        raise last

    def _delete_activation_if_exists(activation_id):
        try:
            ssm.delete_activation(ActivationId=activation_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidActivation":
                raise

    def _track_activation(activation_id):
        ctx.on_cleanup(lambda: _delete_activation_if_exists(activation_id))
        return activation_id

    def _create_ssm_service_role():
        role_name = ctx.unique_name("sim2real-behav-ssm-role-")
        assume = json.dumps(
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
        policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=assume,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

        def _cleanup_role():
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
            iam.delete_role(RoleName=role_name)

        ctx.on_cleanup(_cleanup_role)
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        return role_name

    role = _create_ssm_service_role()
    description = ctx.unique_name("sim2real-behav-probe-activation-")
    create_resp = _call_with_retry(
        lambda: ssm.create_activation(
            IamRole=role,
            Description=description,
            RegistrationLimit=1,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    activation_id = create_resp["ActivationId"]
    _track_activation(activation_id)
    assert create_resp["ActivationCode"], f"expected a non-empty ActivationCode, got {create_resp!r}"

    activations = ssm.describe_activations()["ActivationList"]
    matching = next(a for a in activations if a["ActivationId"] == activation_id)
    assert matching["IamRole"] == role, matching
    assert matching["RegistrationsCount"] == 0, matching
    assert matching["RegistrationLimit"] == 1, matching
    assert matching["Expired"] is False, matching

    ssm.delete_activation(ActivationId=activation_id)
    activations_after = ssm.describe_activations()["ActivationList"]
    assert all(a["ActivationId"] != activation_id for a in activations_after), (
        f"deleted activation {activation_id} still listed in {activations_after}"
    )

    # Deleting an already-deleted activation must be rejected.
    dup_code, dup_message = _error_code(
        lambda: ssm.delete_activation(ActivationId=activation_id)
    )
    assert dup_code == "InvalidActivation", dup_code
    # AWS sends this refusal with an empty message.
    assert dup_message == "", f"expected an empty message, got {dup_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
