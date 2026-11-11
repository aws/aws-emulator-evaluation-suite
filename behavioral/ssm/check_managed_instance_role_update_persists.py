"""managed-instance-role-update-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "managed-instance-role-update-persists"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A hybrid activation keeps its IAM role and has no registered instance until an agent
    checks in; UpdateManagedInstanceRole on an unregistered mi-* id is InvalidInstanceId."""
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
    assert activation["ActivationCode"], (
        "CreateActivation returned an empty ActivationCode for a successful call"
    )
    ctx.on_cleanup(lambda: ssm.delete_activation(ActivationId=activation_id))

    listed = ssm.describe_activations(
        Filters=[{"FilterKey": "ActivationIds", "FilterValues": [activation_id]}]
    )["ActivationList"]
    assert [a["ActivationId"] for a in listed] == [activation_id], (
        f"DescribeActivations did not return exactly the activation just created: {listed!r}"
    )
    created = listed[0]
    assert created["IamRole"] == role_name, (
        f"activation kept IamRole {created['IamRole']!r}, expected {role_name!r}"
    )
    assert created["RegistrationLimit"] == 1, (
        f"activation kept RegistrationLimit 1, expected 1, got {created['RegistrationLimit']!r}"
    )
    assert created.get("RegistrationsCount", 0) == 0, (
        "an activation nothing has registered against must report zero registrations, "
        f"got {created.get('RegistrationsCount')!r}"
    )
    assert created.get("Expired", False) is False, "a just-created activation is not expired"

    # Effect absent: issuing an activation does NOT bring a managed instance into
    # existence -- nothing is registered against it until an agent checks in.
    properties = ssm.describe_instance_properties()["InstanceProperties"]
    assert all(p.get("ActivationId") != activation_id for p in properties), (
        f"a managed instance appeared for activation {activation_id} that no agent registered"
    )

    # ...and the role of an instance that was never registered cannot be updated.
    # `mi-` + 17 hex digits is the ManagedInstanceId pattern, so this reaches the
    # service rather than botocore's client-side validation.
    unregistered_id = "mi-0123456789abcdef0"
    err = _error(
        lambda: ssm.update_managed_instance_role(
            InstanceId=unregistered_id, IamRole=role_name
        )
    )
    assert err["Code"] == "InvalidInstanceId", (
        f"UpdateManagedInstanceRole for an unregistered managed instance should be "
        f"rejected with InvalidInstanceId, got {err!r}"
    )
    expected_message = ""
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
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
