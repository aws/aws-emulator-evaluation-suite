"""create-endpoint-config-invalid-instance-type-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-endpoint-config-invalid-instance-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]

# Registry account IDs for the SageMaker 1P built-in-algorithm ECR images. These images are
# publicly readable cross-account (AWS grants pull access to any customer account/role), so
# they let CreateModel's real "can this role actually pull this image" check succeed without
# us owning a private ECR repo of our own.
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """CreateEndpointConfig with a malformed/unsupported InstanceType is rejected with
    ValidationException rather than stored verbatim."""
    account_id = _BUILTIN_ALGO_REGISTRY.get(ctx.region)
    if account_id is None:
        raise AssertionError(
            f"region {ctx.region} is not in the curated built-in-algorithm ECR registry "
            "map used by this check to source a real, pullable inference image"
        )

    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)

    model_name = ctx.unique_name("sim2real-model-")
    _create_model_retrying_role_propagation(
        sm,
        ModelName=model_name,
        ExecutionRoleArn=role_arn,
        PrimaryContainer={"Image": f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/knn:1"},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_name))


    bad_config = ctx.unique_name("sim2real-epc-bad-")
    code, message = _error(
        lambda: sm.create_endpoint_config(
            EndpointConfigName=bad_config,
            ProductionVariants=[
                {
                    "VariantName": "v1",
                    "ModelName": model_name,
                    "InitialInstanceCount": 1,
                    "InstanceType": "ml.bogus.xlarge",
                }
            ],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    # message varies: it enumerates the full InstanceType enum in hash order, and the
    # set grows with every new instance family.

    # Effect-absence: the rejected config was never persisted.
    not_found_code, not_found_message = _error(
        lambda: sm.describe_endpoint_config(EndpointConfigName=bad_config)
    )
    assert not_found_code == "ValidationException", f"expected missing config lookup to fail, got {not_found_code!r}"
    expected_not_found = f'Could not find endpoint configuration "{bad_config}".'
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )

    # Positive control: the same shape with a valid InstanceType succeeds.
    good_config = ctx.unique_name("sim2real-epc-good-")
    sm.create_endpoint_config(
        EndpointConfigName=good_config,
        ProductionVariants=[
            {
                "VariantName": "v1",
                "ModelName": model_name,
                "InitialInstanceCount": 1,
                "InstanceType": "ml.m5.large",
            }
        ],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_endpoint_config(EndpointConfigName=good_config))
    desc = sm.describe_endpoint_config(EndpointConfigName=good_config)
    got_instance_type = desc["ProductionVariants"][0]["InstanceType"]
    assert got_instance_type == "ml.m5.large", f"expected ml.m5.large, got {got_instance_type!r}"


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_sagemaker_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(2)
    return role["Arn"]


def _create_model_retrying_role_propagation(sm: Any, deadline_s: float = 45.0, **kwargs: Any) -> None:
    """CreateModel can reject a just-created role with ValidationException until IAM
    propagation catches up; retry that specific, bounded condition and re-raise anything else."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            sm.create_model(**kwargs)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "ValidationException" or time.monotonic() >= deadline:
                raise
            time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
