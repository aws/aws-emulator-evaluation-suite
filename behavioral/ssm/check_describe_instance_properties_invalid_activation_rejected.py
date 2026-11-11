"""describe-instance-properties-invalid-activation-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-instance-properties-invalid-activation-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceProperties filtered by a real ActivationId succeeds (even with zero
    registrations against it), but filtering by an unknown ActivationId is rejected with
    InvalidActivationId."""
    ssm = ctx.client("ssm")
    role_name = _create_hybrid_role(ctx)

    activation = _create_activation_with_retry(
        ssm,
        role_name,
        Description="sim2real-behav describe-instance-properties activation",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    activation_id = activation["ActivationId"]
    ctx.on_cleanup(lambda: ssm.delete_activation(ActivationId=activation_id))

    # Positive control: a real ActivationId is an accepted filter value.
    control = ssm.describe_instance_properties(
        InstancePropertyFilterList=[{"key": "ActivationIds", "valueSet": [activation_id]}]
    )
    assert control["InstanceProperties"] == [], (
        f"a fresh activation with zero registrations must filter to no instance "
        f"properties, got {control['InstanceProperties']!r}"
    )

    # Negative: a syntactically malformed ActivationId (not the standard GUID shape) --
    # rejected before any managed-node lookup.
    bad_activation_id = "not-a-valid-activation-id"
    code, message = _error(
        lambda: ssm.describe_instance_properties(
            InstancePropertyFilterList=[
                {"key": "ActivationIds", "valueSet": [bad_activation_id]}
            ]
        )
    )
    assert code == "InvalidActivationId", code
    assert message == f"Invalid Activation Ids {bad_activation_id}", message


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


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
            return ssm.create_activation(IamRole=role_name, **kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ValidationException":
                raise
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"create_activation never succeeded after IAM propagation: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

