"""managed-instance-role-invalid-instance-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "managed-instance-role-invalid-instance-rejected"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateManagedInstanceRole on a well-formed but unknown hybrid instance id fails with
    InvalidInstanceId and the exact message and DescribeInstanceInformation shows no such node, while
    the check's activation is listed with its IamRole."""
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    role_name, _ = _create_ssm_trust_role(ctx, iam, "sim2real-hybrid-role-")
    activation = _retry_on_role_propagation(
        lambda: ssm.create_activation(
            IamRole=role_name,
            RegistrationLimit=1,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    activation_id = activation["ActivationId"]
    ctx.on_cleanup(lambda: ssm.delete_activation(ActivationId=activation_id))

    bogus_instance_id = "mi-" + "0" * 17
    err = _error(
        lambda: ssm.update_managed_instance_role(
            InstanceId=bogus_instance_id, IamRole=role_name
        )
    )
    assert err["Code"] == "InvalidInstanceId", (
        f"UpdateManagedInstanceRole against a nonexistent hybrid instance id should be "
        f"rejected with InvalidInstanceId, got {err!r}"
    )
    expected_message = ""
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # effect absent: the fabricated instance id never became a real managed node.
    info = ssm.describe_instance_information(
        Filters=[{"Key": "InstanceIds", "Values": [bogus_instance_id]}]
    )
    assert info["InstanceInformationList"] == [], (
        f"a rejected, never-registered instance id must not appear as a managed node: "
        f"{info['InstanceInformationList']!r}"
    )

    # positive control: the activation we made is still visible through the control
    # plane -- the whole SSM API isn't just uniformly failing.
    found = _find_activation(ssm, activation_id)
    assert found is not None, f"activation {activation_id} not found via DescribeActivations"
    assert found["IamRole"] == role_name, (
        f"activation kept IamRole {found['IamRole']!r}, expected {role_name!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected success
    raises, so an emulator accepting what AWS refuses never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, the call unexpectedly succeeded: {result!r}")


def _find_activation(ssm, activation_id):
    next_token = None
    for _ in range(50):
        kwargs = {
            "Filters": [{"FilterKey": "ActivationIds", "FilterValues": [activation_id]}]
        }
        if next_token:
            kwargs["NextToken"] = next_token
        page = ssm.describe_activations(**kwargs)
        for item in page.get("ActivationList", []):
            if item["ActivationId"] == activation_id:
                return item
        next_token = page.get("NextToken")
        if not next_token:
            break
    return None


def _create_ssm_trust_role(ctx, iam, name_prefix):
    import json

    role_name = ctx.unique_name(name_prefix)[:64]
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    return role_name, role_arn


def _safe_delete_role(iam, role_name):
    from botocore.exceptions import ClientError

    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _retry_on_role_propagation(fn, timeout_s=45.0, interval_s=3.0):
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            msg = err.response["Error"].get("Message", "")
            if "nonexistent role" in msg.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
