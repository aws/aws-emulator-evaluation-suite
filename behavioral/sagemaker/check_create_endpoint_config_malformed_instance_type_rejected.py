"""create-endpoint-config-malformed-instance-type-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-endpoint-config-malformed-instance-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]

# Registry account IDs for the SageMaker 1P built-in-algorithm ECR images, keyed by region.
# CreateModel rejects a container Image whose ECR region does not match the client's region
# ("Cross region ECR image pulls are not allowed"), so the registry account must follow ctx.region.
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
def run(ctx) -> None:
    """CreateEndpointConfig with a malformed InstanceType fails with ValidationException and no config
    exists afterwards (exact describe message), while the same config with ml.m5.large is created
    and described."""
    sm = ctx.client("sagemaker")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-dummy-role-')}"

    registry_account = _BUILTIN_ALGO_REGISTRY.get(ctx.region)
    if registry_account is None:
        raise AssertionError(
            f"region {ctx.region} is not in the curated built-in-algorithm ECR registry "
            "map used by this check to source a real, same-region inference image"
        )

    model_name = ctx.unique_name("sim2real-model-")
    sm.create_model(
        ModelName=model_name,
        PrimaryContainer={
            "Image": f"{registry_account}.dkr.ecr.{ctx.region}.amazonaws.com/linear-learner:1",
        },
        ExecutionRoleArn=role_arn,
    )
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_name))

    bad_config_name = ctx.unique_name("sim2real-badcfg-")
    code, message = _error(
        lambda: sm.create_endpoint_config(
            EndpointConfigName=bad_config_name,
            ProductionVariants=[
                {
                    "VariantName": "AllTraffic",
                    "ModelName": model_name,
                    "InstanceType": "ml.not-a-real-type.9xlarge",
                    "InitialInstanceCount": 1,
                }
            ],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    # message varies: it enumerates the full InstanceType enum in hash order, and the
    # set grows with every new instance family.

    # (b) effect absent: the rejected config was never created. SageMaker surfaces a
    # missing EndpointConfig as ValidationException, not a distinct not-found code.
    absent_code, absent_message = _error(
        lambda: sm.describe_endpoint_config(EndpointConfigName=bad_config_name)
    )
    assert absent_code == "ValidationException", f"expected ValidationException, got {absent_code}"
    expected_absent = f'Could not find endpoint configuration "{bad_config_name}".'
    assert absent_message == expected_absent, (
        f"expected message {expected_absent!r}, got {absent_message!r}"
    )

    # (c) positive control: identical shape with a real instance type succeeds.
    good_config_name = ctx.unique_name("sim2real-goodcfg-")
    ctx.on_cleanup(lambda: sm.delete_endpoint_config(EndpointConfigName=good_config_name))
    sm.create_endpoint_config(
        EndpointConfigName=good_config_name,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "InstanceType": "ml.m5.large",
                "InitialInstanceCount": 1,
            }
        ],
    )
    described = sm.describe_endpoint_config(EndpointConfigName=good_config_name)
    assert described["EndpointConfigName"] == good_config_name
    assert described["ProductionVariants"][0]["InstanceType"] == "ml.m5.large"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
