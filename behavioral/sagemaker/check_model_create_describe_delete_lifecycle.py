"""model-create-describe-delete-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-create-describe-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

# Registry account IDs for the SageMaker 1P built-in-algorithm ECR images. These images are
# publicly readable cross-account (AWS grants pull access to any customer account/role), so
# they let CreateModel's real "can this role actually pull this image" check succeed without
# us owning a private ECR repo of our own. CreateModel eagerly resolves the image against the
# role -- an unpullable image (e.g. a fabricated registry account) is rejected outright with
# ValidationException, not deferred to deployment time.
#
# The region literals below are legitimate: each is AWS's own fixed, region-pinned registry
# account for this built-in image family, not a stand-in for ctx.region.
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
    """CreateModel returns an ARN ending in model/<name> and describes with that name, ARN, role and
    image; after DeleteModel, DescribeModel and a second DeleteModel are each refused with
    ValidationException and the exact message.
    """
    account_id = _BUILTIN_ALGO_REGISTRY.get(ctx.region)
    assert account_id is not None, (
        f"region {ctx.region} is not in the curated built-in-algorithm ECR registry map "
        "used by this check to source a real, pullable inference image"
    )

    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_execution_role(ctx)
    model_name = ctx.unique_name("sim2real-sm-model-")
    image_uri = f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/knn:1"

    ctx.on_cleanup(lambda: _delete_model_if_present(ctx, model_name))
    created = _retry_role_propagation(
        lambda: sm.create_model(
            ModelName=model_name,
            ExecutionRoleArn=role_arn,
            PrimaryContainer={"Image": image_uri, "Mode": "SingleModel"},
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )
    )
    model_arn = created["ModelArn"]
    assert model_arn.endswith(f"model/{model_name}"), (
        f"expected ModelArn to end with 'model/{model_name}', got {model_arn!r}"
    )

    described = sm.describe_model(ModelName=model_name)
    assert described["ModelName"] == model_name, (
        f"expected DescribeModel ModelName {model_name!r}, got {described['ModelName']!r}"
    )
    assert described["ModelArn"] == model_arn, (
        f"expected DescribeModel ModelArn {model_arn!r}, got {described['ModelArn']!r}"
    )
    assert described["ExecutionRoleArn"] == role_arn, (
        f"expected DescribeModel ExecutionRoleArn {role_arn!r}, got "
        f"{described.get('ExecutionRoleArn')!r}"
    )
    assert described["PrimaryContainer"]["Image"] == image_uri, (
        f"expected DescribeModel container image {image_uri!r}, got "
        f"{described['PrimaryContainer']['Image']!r}"
    )

    sm.delete_model(ModelName=model_name)

    code, message = _error(lambda: sm.describe_model(ModelName=model_name))
    assert code == "ValidationException", (
        f"expected DescribeModel on a deleted model to raise ValidationException, got {code!r}"
    )
    expected_message = f'Could not find model "{model_name}".'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    redelete_code, redelete_message = _error(lambda: sm.delete_model(ModelName=model_name))
    assert redelete_code == "ValidationException", (
        f"expected a second DeleteModel on the same now-gone name to also fail with "
        f"ValidationException, got {redelete_code!r}"
    )
    expected_message = f'Could not find model "{model_name}".'
    assert redelete_message == expected_message, (
        f"expected message {expected_message!r}, got {redelete_message!r}"
    )


def _delete_model_if_present(ctx, model_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_model(ModelName=model_name)
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ValidationException" and err.get("Message", "").startswith("Could not find"):
            return  # SageMaker's not-found answer for a model
        if err["Code"] != "ResourceNotFound":
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


def _create_sagemaker_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-model-role-")
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_sagemaker_trust_policy())
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    """Poll a call that depends on a freshly-created IAM role until IAM's eventual
    consistency window closes, rather than a fixed sleep."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
