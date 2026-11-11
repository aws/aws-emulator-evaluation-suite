"""endpoint-resource-limit-enforced-server-side."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "endpoint-resource-limit-enforced-server-side"
GROUP = "server-side"
SERVICES = ["sagemaker"]

# Registry account IDs for the SageMaker 1P built-in-algorithm ECR images. These images are
# publicly readable cross-account, so CreateModel's real "can this role actually pull this
# image" check (it rejects an image it cannot pull with ValidationException,
# even before any pull is attempted) succeeds without owning a private ECR repo.
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEndpoint for an instance type the account has zero hosting quota for fails
    ResourceLimitExceeded and creates no endpoint, while an endpoint on a commonly available
    instance type is created."""
    registry_account = _BUILTIN_ALGO_REGISTRY.get(ctx.region)
    if registry_account is None:
        raise AssertionError(
            f"region {ctx.region} is not in the curated built-in-algorithm ECR registry map "
            "used by this check to source a real, pullable inference image"
        )

    sm = ctx.client("sagemaker")
    teardown = {}
    role_arn = _create_sm_execution_role(ctx)
    model_name = _create_dummy_model(ctx, role_arn, registry_account)

    # --- negative: an instance type the account has zero default hosting quota for.
    over_quota_config = ctx.unique_name("sim2real-epc-overquota-")
    sm.create_endpoint_config(
        EndpointConfigName=over_quota_config,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "InstanceType": "ml.p4de.24xlarge",  # large-instance: zero default quota; refused, launches nothing
                "InitialInstanceCount": 1,
            }
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: sm.delete_endpoint_config(EndpointConfigName=over_quota_config))
    )

    over_quota_endpoint = ctx.unique_name("sim2real-ep-overquota-")
    # Registered before the call, not after a confirmed rejection: if the target is
    # over-permissive and actually creates this (cost-accruing) endpoint, it must still be
    # torn down.
    ctx.on_cleanup(lambda: _delete_endpoint_and_wait(sm, over_quota_endpoint, teardown))
    code, message = _error(
        lambda: sm.create_endpoint(
            EndpointName=over_quota_endpoint,
            EndpointConfigName=over_quota_config,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    assert code == "ResourceLimitExceeded", f"expected ResourceLimitExceeded, got {code}"
    expected = (
        "The account-level service limit 'ml.p4de.24xlarge for endpoint usage' is 0 Instances, "  # large-instance: text
        "with current utilization of 0 Instances and a request delta of 1 Instances. Please use "
        "AWS Service Quotas to request an increase for this quota. If AWS Service Quotas is not "
        "available, contact AWS support to request an increase for this quota."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no endpoint object was ever created under that name.
    listed = sm.list_endpoints(NameContains=over_quota_endpoint)["Endpoints"]
    assert listed == [], f"endpoint should not exist after rejection, found {listed}"

    # --- positive control: a quota-available instance type. The config carries an execution role
    # and no model (it hosts inference components), so no container health check keeps the
    # endpoint Creating and it reaches InService and deletes in minutes.
    ok_config = ctx.unique_name("sim2real-epc-ok-")
    _retry_role_propagation(
        lambda: sm.create_endpoint_config(
            EndpointConfigName=ok_config,
            ExecutionRoleArn=role_arn,
            ProductionVariants=[
                {
                    "VariantName": "AllTraffic",
                    "InstanceType": "ml.c5.large",
                    "InitialInstanceCount": 1,
                }
            ],
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_endpoint_config(EndpointConfigName=ok_config)))

    ok_endpoint = ctx.unique_name("sim2real-ep-ok-")
    ctx.on_cleanup(lambda: _delete_endpoint_and_wait(sm, ok_endpoint, teardown))
    resp = sm.create_endpoint(
        EndpointName=ok_endpoint,
        EndpointConfigName=ok_config,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    assert resp["EndpointArn"].endswith(ok_endpoint)


def _delete_endpoint_and_wait(sm, endpoint_name, teardown) -> None:
    """Delete the endpoint once DeleteEndpoint stops answering "Cannot update in-progress endpoint",
    then wait for DescribeEndpoint to answer "Could not find endpoint", every 2 s to a teardown
    deadline 1140 s out, inside the suite's 1200 s cleanup budget."""
    if "deadline" not in teardown:
        teardown["deadline"] = time.monotonic() + 1140.0
    deadline = teardown["deadline"]
    deleted = False
    while True:
        try:
            if not deleted:
                sm.delete_endpoint(EndpointName=endpoint_name)
                deleted = True
            sm.describe_endpoint(EndpointName=endpoint_name)
        except ClientError as exc:
            err = exc.response["Error"]
            message = err.get("Message", "")
            if err["Code"] != "ValidationException":
                raise
            if message.startswith("Could not find endpoint"):
                return
            if not message.startswith("Cannot update in-progress endpoint"):
                raise
        if time.monotonic() >= deadline:
            raise TimeoutError(f"endpoint {endpoint_name} still present at the teardown deadline")
        time.sleep(2)


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFound"):
            raise


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _create_sm_execution_role(ctx) -> str:
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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    # Cleanups run last-registered first, so the detach runs before DeleteRole (DeleteConflict).
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    return resp["Role"]["Arn"]


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    """Poll a call that depends on a freshly-created IAM role until IAM's eventual
    consistency window closes, instead of a fixed sleep."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "").lower()
            # A propagation-delay rejection names the role as not-yet-assumable; a permanent
            # rejection is a different failure and must not be retried into a false pass.
            if code == "ValidationException" and "role" in message and "assum" in message:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _create_dummy_model(ctx, role_arn: str, registry_account: str) -> str:
    sm = ctx.client("sagemaker")
    model_name = ctx.unique_name("sim2real-model-")
    image = f"{registry_account}.dkr.ecr.{ctx.region}.amazonaws.com/knn:1"
    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_model(ModelName=model_name)))
    _retry_role_propagation(
        lambda: sm.create_model(
            ModelName=model_name,
            ExecutionRoleArn=role_arn,
            PrimaryContainer={"Image": image},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    return model_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
