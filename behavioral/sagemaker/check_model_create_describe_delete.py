"""model-create-describe-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

# Registry account IDs for the SageMaker 1P built-in-algorithm ECR images. These images are
# publicly readable cross-account, so CreateModel's real "can this role actually pull this
# image" check (it rejects an image it cannot pull with ValidationException, even before any
# pull is attempted) succeeds without owning a private ECR repo.
_BUILTIN_ALGO_REGISTRY = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-south-1": "991648021394",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "712309505854",
    "ca-central-1": "469771592824",
    "eu-central-1": "664544806723",
    "eu-north-1": "669576153137",
    "eu-west-1": "438346466558",
    "eu-west-2": "644912444149",
    "eu-west-3": "749696950732",
    "sa-east-1": "855470959533",
}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModel describes with its name, role and container image; after DeleteModel, DescribeModel is
    refused with ValidationException and its exact message, and the freed ModelName can be used for a new
    model.
    """
    registry_account = _BUILTIN_ALGO_REGISTRY.get(ctx.region)
    if registry_account is None:
        raise AssertionError(
            f"region {ctx.region} is not in the curated built-in-algorithm ECR registry map "
            "used by this check to source a real, pullable inference image"
        )

    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)
    model_name = ctx.unique_name("sim2real-sm-model-")
    image = f"{registry_account}.dkr.ecr.{ctx.region}.amazonaws.com/knn:1"

    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_model(ModelName=model_name)))

    _retry_role_propagation(
        lambda: sm.create_model(
            ModelName=model_name,
            ExecutionRoleArn=role_arn,
            PrimaryContainer={"Image": image, "Mode": "SingleModel"},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )

    desc = sm.describe_model(ModelName=model_name)
    assert desc["ModelName"] == model_name, f"expected ModelName {model_name!r}, got {desc.get('ModelName')!r}"
    assert desc["ExecutionRoleArn"] == role_arn, (
        f"expected ExecutionRoleArn {role_arn!r}, got {desc.get('ExecutionRoleArn')!r}"
    )
    assert desc["PrimaryContainer"]["Image"] == image, (
        f"expected PrimaryContainer.Image {image!r}, got {desc.get('PrimaryContainer', {}).get('Image')!r}"
    )

    sm.delete_model(ModelName=model_name)

    code, message = _error(lambda: sm.describe_model(ModelName=model_name))
    assert code == "ValidationException", f"expected ValidationException after delete, got {code!r}"
    expected_message = f'Could not find model "{model_name}".'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the freed name is reusable: SageMaker does not reserve a deleted model's ModelName
    sm.create_model(
        ModelName=model_name,
        ExecutionRoleArn=role_arn,
        PrimaryContainer={"Image": image, "Mode": "SingleModel"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    redesc = sm.describe_model(ModelName=model_name)
    assert redesc["ModelName"] == model_name, (
        f"expected recreated model {model_name!r} to be describable, got {redesc.get('ModelName')!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFound"):
            raise


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _sagemaker_trust_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sagemaker.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _create_sagemaker_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_sagemaker_trust_policy(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _safe(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    """Poll a call that depends on a freshly-created IAM role until IAM's eventual
    consistency window closes, rather than a fixed sleep."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "").lower()
            # A propagation-delay rejection names the role as not-yet-assumable; a permanent
            # rejection (e.g. an image the role is not entitled to pull) is a different failure
            # and must not be retried into a false pass.
            if code == "ValidationException" and "role" in message and "assum" in message:
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
