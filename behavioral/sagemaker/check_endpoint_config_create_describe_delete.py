"""endpoint-config-create-describe-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "endpoint-config-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEndpointConfig persists the ProductionVariant it was given; after DeleteEndpointConfig,
    DescribeEndpointConfig and a second delete are each refused with ValidationException
    'Could not find endpoint configuration "<name>".'."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)
    model_name = ctx.unique_name("sim2real-sm-model-")
    config_name = ctx.unique_name("sim2real-sm-epc-")
    image = f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-inference:1.12.1-cpu-py38"

    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_model(ModelName=model_name)))
    _retry_role_propagation(
        lambda: sm.create_model(
            ModelName=model_name,
            ExecutionRoleArn=role_arn,
            PrimaryContainer={"Image": image, "Mode": "SingleModel"},
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
    )

    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_endpoint_config(EndpointConfigName=config_name)))
    sm.create_endpoint_config(
        EndpointConfigName=config_name,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "InitialInstanceCount": 1,
                "InstanceType": "ml.m5.large",
                "InitialVariantWeight": 1.0,
            }
        ],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    desc = sm.describe_endpoint_config(EndpointConfigName=config_name)
    assert desc["EndpointConfigName"] == config_name, (
        f"expected DescribeEndpointConfig to echo back {config_name!r}, got {desc['EndpointConfigName']!r}"
    )
    variants = desc["ProductionVariants"]
    assert len(variants) == 1, f"expected exactly 1 ProductionVariant, got {len(variants)}"
    assert variants[0]["ModelName"] == model_name, (
        f"expected persisted ModelName {model_name!r}, got {variants[0]['ModelName']!r}"
    )
    assert variants[0]["InstanceType"] == "ml.m5.large", (
        f"expected persisted InstanceType 'ml.m5.large', got {variants[0]['InstanceType']!r}"
    )
    assert variants[0]["InitialInstanceCount"] == 1, (
        f"expected persisted InitialInstanceCount 1, got {variants[0]['InitialInstanceCount']!r}"
    )

    sm.delete_endpoint_config(EndpointConfigName=config_name)

    code, message = _error(lambda: sm.describe_endpoint_config(EndpointConfigName=config_name))
    assert code == "ValidationException", (
        f"expected DescribeEndpointConfig on a deleted config to fail with ValidationException, got {code!r}"
    )
    expected = f'Could not find endpoint configuration "{config_name}".'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    redelete_code, redelete_message = _error(lambda: sm.delete_endpoint_config(EndpointConfigName=config_name))
    assert redelete_code == "ValidationException", (
        f"expected a second DeleteEndpointConfig on the same dead id to also fail with "
        f"ValidationException, got {redelete_code!r}"
    )
    expected = f'Could not find endpoint configuration "{config_name}".'
    assert redelete_message == expected, f"expected message {expected!r}, got {redelete_message!r}"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ValidationException" and err.get("Message", "").startswith("Could not find"):
            return  # SageMaker's not-found answer for an endpoint, config or model
        if err["Code"] not in ("NoSuchEntity", "ResourceNotFound"):
            raise


def _error(fn):
    """Call fn(); return its (code, message). A success raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
