"""create-endpoint-concurrent-duplicate-name-race."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-endpoint-concurrent-duplicate-name-race"
GROUP = "concurrency"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateEndpoint calls for the same new EndpointName resolve deterministically:
    exactly one wins and creates the endpoint, the other is rejected with ValidationException, and
    no duplicate endpoint is created."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_execution_role(ctx)

    model_name = ctx.unique_name("sim2real-behav-model-")
    # CreateModel checks synchronously that the execution role can pull the image (a nonexistent ECR
    # image fails with ValidationException), so the race needs a pullable image and a role with
    # ECR pull permission.
    image = f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-inference:1.12.1-cpu-py38"
    _create_model_with_retry(
        sm,
        ModelName=model_name,
        PrimaryContainer={"Image": image},
        ExecutionRoleArn=role_arn,
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_name))

    config_name = ctx.unique_name("sim2real-behav-epc-")
    # Serverless avoids pinning an always-on instance type (ml.t2.medium is a deprecated
    # CreateEndpointConfig instance type) and needs no
    # standing ml.* instance for this control-plane race.
    sm.create_endpoint_config(
        EndpointConfigName=config_name,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "ServerlessConfig": {"MemorySizeInMB": 1024, "MaxConcurrency": 1},
            }
        ],
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: sm.delete_endpoint_config(EndpointConfigName=config_name))

    endpoint_name = ctx.unique_name("sim2real-behav-ep-")
    barrier = threading.Barrier(2)

    def _create():
        barrier.wait()
        try:
            sm.create_endpoint(
                EndpointName=endpoint_name,
                EndpointConfigName=config_name,
                Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
            )
            return ("ok", None)
        except ClientError as exc:
            return ("err", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [f.result() for f in [pool.submit(_create) for _ in range(2)]]

    ctx.on_cleanup(lambda: _delete_endpoint_best_effort(sm, endpoint_name))

    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o for o in outcomes if o[0] == "err"]
    assert len(successes) == 1, f"expected exactly one winner, got {outcomes}"
    assert len(failures) == 1, f"expected exactly one rejection, got {outcomes}"
    assert failures[0][1][0] == "ValidationException", f"unexpected rejection: {failures[0][1]!r}"

    # Confirm exactly one endpoint resource exists and it points at our config (no
    # duplicate/second endpoint silently created under the hood by the loser).
    described = sm.describe_endpoint(EndpointName=endpoint_name)
    assert described["EndpointConfigName"] == config_name
    expected = f'Cannot create already existing endpoint "{described["EndpointArn"]}".'
    assert failures[0][1][1] == expected, f"expected rejection message {expected!r}, got {failures[0][1][1]!r}"


# ===== helpers =====
_ROLE_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_SAGEMAKER_FULL_ACCESS_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
_ECR_READONLY_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"


def _create_sagemaker_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_ROLE_TRUST_POLICY),
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SAGEMAKER_FULL_ACCESS_POLICY_ARN)
    # CreateModel checks this at creation time (see the call site) -- the role needs its own
    # ecr:GetAuthorizationToken/BatchGetImage grant to pull even a publicly-pullable image.
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_ECR_READONLY_POLICY_ARN)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_SAGEMAKER_FULL_ACCESS_POLICY_ARN)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_ECR_READONLY_POLICY_ARN)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(1)
    return role_arn


def _create_model_with_retry(sm, *, timeout_s: float = 60.0, interval_s: float = 5.0, **kwargs) -> None:
    # A freshly created role can fail CreateModel with a transient ValidationException until its
    # trust grant propagates; that specific error is retried to a deadline.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.create_model(**kwargs)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _delete_endpoint_best_effort(sm, name: str, timeout_s: float = 600.0) -> None:
    """Delete the endpoint, retrying the ValidationException a still-Creating endpoint answers;
    return once it is not found, raise everything else."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.delete_endpoint(EndpointName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "Could not find" in message:
                return
            if code != "ValidationException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
