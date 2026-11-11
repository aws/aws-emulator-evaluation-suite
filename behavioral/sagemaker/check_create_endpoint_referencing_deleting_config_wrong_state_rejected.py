"""create-endpoint-referencing-deleting-config-wrong-state-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-endpoint-referencing-deleting-config-wrong-state-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEndpoint referencing an already-deleted EndpointConfig is rejected as nonexistent.
    EndpointConfig deletion is synchronous, so there is no mid-deletion window to race."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)

    model_name = ctx.unique_name("sim2real-model-")
    sm.create_model(
        ModelName=model_name,
        ExecutionRoleArn=role_arn,
        PrimaryContainer={
            "Image": f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-inference:1.12.1-cpu-py38"
        },
    )
    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_model(ModelName=model_name)))

    doomed_config = ctx.unique_name("sim2real-epc-doomed-")
    sm.create_endpoint_config(
        EndpointConfigName=doomed_config,
        ProductionVariants=[_variant(model_name)],
    )
    sm.delete_endpoint_config(EndpointConfigName=doomed_config)

    # independent read proving the delete actually took: the config no longer describes.
    describe_config_code, describe_config_message = _error(
        lambda: sm.describe_endpoint_config(EndpointConfigName=doomed_config)
    )
    assert describe_config_code == "ValidationException", (
        f"expected the deleted config to read as gone via ValidationException, got {describe_config_code!r}"
    )
    expected_describe = f'Could not find endpoint configuration "{doomed_config}".'
    assert describe_config_message == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_config_message!r}"
    )

    endpoint_name = ctx.unique_name("sim2real-ep-")
    code, message = _error(
        lambda: sm.create_endpoint(EndpointName=endpoint_name, EndpointConfigName=doomed_config)
    )
    assert code == "ValidationException", f"unexpected rejection code: {code}"
    expected = f'Could not find endpoint configuration "{doomed_config}".'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed = sm.list_endpoints(NameContains=endpoint_name)["Endpoints"]
    assert not listed, f"an endpoint was created despite the missing config: {listed}"

    live_config = ctx.unique_name("sim2real-epc-live-")
    sm.create_endpoint_config(
        EndpointConfigName=live_config,
        ProductionVariants=[_variant(model_name)],
    )
    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_endpoint_config(EndpointConfigName=live_config)))

    sm.create_endpoint(EndpointName=endpoint_name, EndpointConfigName=live_config)
    ctx.on_cleanup(lambda: _delete_endpoint_when_settled(sm, endpoint_name))
    desc = sm.describe_endpoint(EndpointName=endpoint_name)
    assert desc["EndpointStatus"] in ("Creating", "InService"), (
        f"expected Creating or InService for a valid config, got {desc['EndpointStatus']!r}"
    )


def _variant(model_name: str) -> dict:
    return {
        "VariantName": "AllTraffic",
        "ModelName": model_name,
        "InitialInstanceCount": 1,
        "InstanceType": "ml.m5.large",
        "InitialVariantWeight": 1.0,
    }


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFound"):
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_sagemaker_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    # CreateModel checks that the role can pull the image, so the role needs ECR read permissions:
    # the AWS Deep Learning Container's registry grants pull to every account, but the assumed role
    # still needs ecr:GetAuthorizationToken/BatchGetImage.
    ecr_policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=ecr_policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=ecr_policy_arn)))
    return arn


def _delete_endpoint_when_settled(sm, endpoint_name, timeout_s=1200.0, interval_s=15.0):
    """DeleteEndpoint refuses an endpoint that is still Creating/Updating, so wait for a
    settled status (bounded, raising on timeout) and then delete; an endpoint that is
    already gone is fine."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = sm.describe_endpoint(EndpointName=endpoint_name)["EndpointStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationException":
                return
            raise
        if status not in ("Creating", "Updating", "SystemUpdating", "RollingBack", "Deleting"):
            break
        if status == "Deleting":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"endpoint {endpoint_name} still {status} after {timeout_s}s")
        time.sleep(interval_s)
    sm.delete_endpoint(EndpointName=endpoint_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
