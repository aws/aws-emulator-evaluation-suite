"""update-managed-instance-role-invalid-instance-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-managed-instance-role-invalid-instance-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]

_BOGUS_MANAGED_INSTANCE_ID = "mi-00000000000000000"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateManagedInstanceRole is rejected with InvalidInstanceId for a well-formed but
    non-existent managed-instance id; the id never shows up as a managed node afterwards, and
    IamRole-accepting SSM control-plane calls otherwise work fine in the same account/region."""
    ssm = ctx.client("ssm")
    role_name = _create_hybrid_role(ctx)

    code, message = _error(
        lambda: ssm.update_managed_instance_role(
            InstanceId=_BOGUS_MANAGED_INSTANCE_ID,
            IamRole=role_name,
        )
    )
    assert code == "InvalidInstanceId", (
        f"expected UpdateManagedInstanceRole for a well-formed but nonexistent managed "
        f"instance id to be rejected with InvalidInstanceId, got {code!r}"
    )
    assert message == "", f"unexpected message: {message!r}"

    # Effect absent: the fabricated managed-instance id never became a real managed node.
    info = ssm.describe_instance_information(
        Filters=[{"Key": "InstanceIds", "Values": [_BOGUS_MANAGED_INSTANCE_ID]}]
    )
    assert info["InstanceInformationList"] == [], (
        f"bogus managed-instance id {_BOGUS_MANAGED_INSTANCE_ID!r} unexpectedly appeared in "
        f"DescribeInstanceInformation: {info['InstanceInformationList']!r}"
    )

    # Positive control: IamRole-accepting SSM APIs are not blanket-broken -- creating a hybrid
    # activation (which also takes an IamRole string, with a properly trust-configured role)
    # succeeds normally in this account/region.
    activation = _create_activation_with_retry(
        ssm, role_name, Description="sim2real-behav update-managed-instance-role control"
    )
    activation_id = activation["ActivationId"]
    ctx.on_cleanup(lambda: ssm.delete_activation(ActivationId=activation_id))

    # Terminal read: an independent DescribeActivations call, not the CreateActivation
    # response itself, confirms the control-plane call actually stuck.
    listed = ssm.describe_activations(
        Filters=[{"FilterKey": "ActivationIds", "FilterValues": [activation_id]}]
    )["ActivationList"]
    assert len(listed) == 1 and listed[0]["ActivationId"] == activation_id, (
        f"expected the positive-control activation {activation_id!r} to be independently "
        f"visible through DescribeActivations, got {listed!r}"
    )
    assert listed[0]["IamRole"] == role_name, (
        f"activation kept IamRole {listed[0]['IamRole']!r}, expected {role_name!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_hybrid_role(ctx) -> str:
    """Create an IAM role trusted by ssm.amazonaws.com (required for CreateActivation's
    IamRole) with the standard hybrid managed-instance permissions policy attached."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-hybrid-role-")
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
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY_ARN)
    )
    return role_name


def _create_activation_with_retry(ssm, role_name: str, **kwargs):
    """CreateActivation validates the role's trust policy server-side; retry through the
    IAM eventual-consistency window instead of a bare sleep."""
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ssm.create_activation(
                IamRole=role_name,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
                **kwargs,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ValidationException":
                raise
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"create_activation never succeeded after IAM propagation: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
