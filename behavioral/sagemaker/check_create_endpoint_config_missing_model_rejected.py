"""create-endpoint-config-missing-model-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-endpoint-config-missing-model-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEndpointConfig referencing a model name that does not exist is rejected, not silently accepted."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)

    bogus_model_name = ctx.unique_name("sim2real-behav-nomodel-")
    bad_config_name = ctx.unique_name("sim2real-behav-epc-bad-")

    code, message = _error(lambda: sm.create_endpoint_config(
        EndpointConfigName=bad_config_name,
        ProductionVariants=[{
            "VariantName": "AllTraffic",
            "ModelName": bogus_model_name,
            "InitialInstanceCount": 1,
            "InstanceType": "ml.m5.large",
        }],
    ))
    assert code == "ValidationException", (
        f"expected CreateEndpointConfig referencing a nonexistent model to be rejected with "
        f"ValidationException, got {code!r}"
    )
    expected = f'Could not find model "{bogus_model_name}".'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the endpoint config was never persisted
    describe_code, describe_message = _error(
        lambda: sm.describe_endpoint_config(EndpointConfigName=bad_config_name)
    )
    assert describe_code == "ValidationException", (
        f"expected the rejected endpoint config {bad_config_name!r} to not exist "
        f"(ValidationException on describe), got {describe_code!r}"
    )
    expected_describe = f'Could not find endpoint configuration "{bad_config_name}".'
    assert describe_message == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_message!r}"
    )

    # positive control: the same shape succeeds when ModelName references a real model
    model_name = ctx.unique_name("sim2real-behav-model-")
    image_uri = _resolve_xgboost_image_uri(ctx)
    _retry_role_propagation(lambda: sm.create_model(
        ModelName=model_name,
        ExecutionRoleArn=role_arn,
        PrimaryContainer={"Image": image_uri},
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    ))
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_name))

    good_config_name = ctx.unique_name("sim2real-behav-epc-good-")
    resp = sm.create_endpoint_config(
        EndpointConfigName=good_config_name,
        ProductionVariants=[{
            "VariantName": "AllTraffic",
            "ModelName": model_name,
            "InitialInstanceCount": 1,
            "InstanceType": "ml.m5.large",
        }],
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_endpoint_config(EndpointConfigName=good_config_name))
    assert resp["EndpointConfigArn"].endswith(good_config_name), (
        f"expected the positive-control endpoint config ARN to end with {good_config_name!r}, "
        f"got {resp['EndpointConfigArn']!r}"
    )

    # terminal read: an independent DescribeEndpointConfig, not the CreateEndpointConfig response
    good_desc = sm.describe_endpoint_config(EndpointConfigName=good_config_name)
    described_model = good_desc["ProductionVariants"][0]["ModelName"]
    assert described_model == model_name, (
        f"expected the independent read of {good_config_name!r} to show ModelName={model_name!r}, "
        f"got {described_model!r}"
    )


def _resolve_xgboost_image_uri(ctx):
    """The SDK resolves the region's built-in XGBoost image; a missing SDK raises ImportError."""
    from sagemaker import image_uris

    return image_uris.retrieve(framework="xgboost", region=ctx.region, version="1.5-1")


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_role_propagation(fn, timeout_s=30.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("AccessDeniedException", "ValidationException"):
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-smrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(1.0)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
