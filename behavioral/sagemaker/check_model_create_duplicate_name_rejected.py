"""model-create-duplicate-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-create-duplicate-name-rejected"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateModel with an existing ModelName is rejected and leaves the original container
    definition untouched, while a differently-named model still creates (positive control)."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)
    name = ctx.unique_name("sim2real-model-")
    original_image = (
        f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-inference:1.12.1-cpu-py38"
    )
    conflicting_image = (
        f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-inference:1.13.1-cpu-py39"
    )

    model_arn = _retry_role_propagation(
        ctx,
        lambda: sm.create_model(
            ModelName=name,
            PrimaryContainer={"Image": original_image},
            ExecutionRoleArn=role_arn,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        ),
    )["ModelArn"]
    ctx.on_cleanup(lambda: _delete_model_ignore(sm, name))

    code, message = _error(
        lambda: sm.create_model(
            ModelName=name,
            PrimaryContainer={"Image": conflicting_image},
            ExecutionRoleArn=role_arn,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = f'Cannot create already existing model "{model_arn}".'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the original model's container definition was not overwritten
    desc = sm.describe_model(ModelName=name)
    assert desc["PrimaryContainer"]["Image"] == original_image, (
        f"expected original image {original_image!r} to survive the rejected duplicate "
        f"create, got {desc['PrimaryContainer']['Image']!r}"
    )

    # positive control: a distinct model name still creates successfully in the same run
    other_name = ctx.unique_name("sim2real-model-ctrl-")
    sm.create_model(
        ModelName=other_name,
        PrimaryContainer={"Image": original_image},
        ExecutionRoleArn=role_arn,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_model_ignore(sm, other_name))
    ctrl_desc = sm.describe_model(ModelName=other_name)
    assert ctrl_desc["ModelName"] == other_name, (
        f"expected control model {other_name!r} to describe back its own name, "
        f"got {ctrl_desc['ModelName']!r}"
    )
    assert ctrl_desc["PrimaryContainer"]["Image"] == original_image, (
        f"expected control model's container image {original_image!r}, "
        f"got {ctrl_desc['PrimaryContainer']['Image']!r}"
    )


def _create_sagemaker_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # CreateModel synchronously verifies the role can pull the container image, so the role
    # needs real ECR read permissions for the public Deep Learning Container image used above.
    ecr_policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=ecr_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=ecr_policy_arn))
    return arn


def _retry_role_propagation(ctx, fn, timeout_s: float = 90.0):
    """Retry fn on the ValidationException SageMaker returns while a new role or its ECR policy
    is still propagating; any other error, or one past the deadline, raises."""
    left = ctx.time_left()
    timeout_s = timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0))
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response["Error"]
            message = err.get("Message", "").lower()
            propagating = err.get("Code") == "ValidationException" and ("role" in message or "pull" in message)
            if not propagating or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises,
    because accepting a call AWS refuses is a failure, not a message mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_model_ignore(sm, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sm.delete_model(ModelName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
