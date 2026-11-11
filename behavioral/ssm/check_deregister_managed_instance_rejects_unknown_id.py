"""deregister-managed-instance-rejects-unknown-id."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-managed-instance-rejects-unknown-id"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

_BOGUS_INSTANCE_ID = "mi-0123456789abcdef0"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterManagedInstance rejects a valid-format but unknown hybrid managed-instance id with
    InvalidInstanceId and the id never appears as a managed node; a CreateActivation positive
    control shows the rejection is specific to the bogus id."""

    ssm = ctx.client("ssm")

    code, message = _error(
        ssm, lambda: ssm.deregister_managed_instance(InstanceId=_BOGUS_INSTANCE_ID)
    )
    assert code == "InvalidInstanceId", f"expected InvalidInstanceId, got {code!r}"
    # AWS sends this InvalidInstanceId with an empty message.
    assert message == "", message

    # Independent read at the destination, through a different operation than the
    # mutating call: the fabricated id never became a real managed node.
    info = ssm.describe_instance_information(
        Filters=[{"Key": "InstanceIds", "Values": [_BOGUS_INSTANCE_ID]}]
    )
    assert info["InstanceInformationList"] == [], (
        f"bogus id unexpectedly appeared as a managed node: {info['InstanceInformationList']}"
    )

    # Positive control: IamRole-accepting SSM hybrid-registration calls are not
    # blanket-broken -- creating an activation with a properly trust-configured role
    # succeeds normally here, and the created activation is independently observable.
    role_name = _create_hybrid_role(ctx)
    activation = _create_activation_with_retry(ssm, role_name)
    activation_id = activation["ActivationId"]
    ctx.on_cleanup(lambda: ssm.delete_activation(ActivationId=activation_id))

    found = _find_activation(ssm, activation_id)
    assert found is not None, f"activation {activation_id} not visible via DescribeActivations"
    assert found["IamRole"] == role_name, (
        f"expected IamRole {role_name!r}, got {found['IamRole']!r}"
    )


def _error(ssm, fn):
    """Call fn() and return its error (Code, Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        f"real AWS rejects DeregisterManagedInstance for an unregistered instance id, "
        f"but it SUCCEEDED and returned {result!r}"
    )


def _create_hybrid_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-hybrid-role-")
    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ssm.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY_ARN)
    )
    return role_name


def _create_activation_with_retry(ssm, role_name, timeout_s=60.0, interval_s=5.0):
    """CreateActivation validates the role's trust policy server-side; retry through the
    IAM eventual-consistency window instead of a bare sleep."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ssm.create_activation(
                IamRole=role_name,
                Description="sim2real-behav deregister-managed-instance control",
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ValidationException":
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"create_activation never succeeded after IAM propagation: {last_err}")


def _find_activation(ssm, activation_id):
    next_token = None
    for _ in range(50):
        kwargs = {"Filters": [{"FilterKey": "ActivationIds", "FilterValues": [activation_id]}]}
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
