"""inference-component-requires-inservice-endpoint-accepted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "inference-component-requires-inservice-endpoint-accepted"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInferenceComponent against a non-InService Endpoint is accepted, but the
    component's CurrentCopyCount stays at 0 until the Endpoint reaches InService, at which
    point it converges to DesiredCopyCount; DeleteInferenceComponent removes it afterwards."""
    sm = ctx.client("sagemaker")
    role_arn = _create_execution_role(ctx)
    check_tags = [{"Key": "sim2real-check", "Value": CHECK}]
    artifact_url = _create_model_artifact(ctx)

    endpoint_config_name = ctx.unique_name("sim2real-behav-epc-")
    endpoint_name = ctx.unique_name("sim2real-behav-ep-")
    ic_name = ctx.unique_name("sim2real-behav-ic-")
    variant_name = "AllTraffic"

    _create_endpoint_config_with_retry(
        sm,
        EndpointConfigName=endpoint_config_name,
        ExecutionRoleArn=role_arn,
        ProductionVariants=[
            {
                "VariantName": variant_name,
                "InstanceType": "ml.c5.large",
                "InitialInstanceCount": 1,
            }
        ],
        Tags=check_tags,
    )
    ctx.on_cleanup(lambda: _delete_endpoint_config_best_effort(sm, endpoint_config_name))

    sm.create_endpoint(
        EndpointName=endpoint_name, EndpointConfigName=endpoint_config_name, Tags=check_tags
    )
    ctx.on_cleanup(lambda: _delete_endpoint_best_effort(sm, endpoint_name))

    spec = {
        "Container": {
            # A pullable AWS Deep Learning Container: CreateInferenceComponent synchronously
            # verifies the role can pull the image.
            "Image": f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-inference:1.12.1-cpu-py38",
            "ArtifactUrl": artifact_url,
        },
        "ComputeResourceRequirements": {
            "MinMemoryRequiredInMb": 1024,
            "NumberOfCpuCoresRequired": 1,
        },
    }

    # Every in-window observation is bracketed by a DescribeEndpoint that must still read
    # Creating; provisioning takes minutes, so the window holds.
    initial_status = _endpoint_status_in_window(sm, endpoint_name)
    assert initial_status == "Creating", f"expected a freshly created endpoint to read Creating, got {initial_status!r}"

    create_resp = _create_inference_component_retry_role_propagation(
        sm,
        InferenceComponentName=ic_name,
        EndpointName=endpoint_name,
        VariantName=variant_name,
        Specification=spec,
        RuntimeConfig={"CopyCount": 1},
        Tags=check_tags,
    )
    ctx.on_cleanup(lambda: _delete_ic_best_effort(sm, ic_name))
    assert create_resp["InferenceComponentArn"].endswith(ic_name), (
        f"expected CreateInferenceComponent to accept the request immediately (SageMaker queues "
        f"deployment rather than rejecting it while the endpoint is not InService), got arn "
        f"{create_resp['InferenceComponentArn']!r}"
    )

    # It is accepted, but not yet deployed: the endpoint is still not InService, so no copy of
    # the component can have started running.
    ic_desc = sm.describe_inference_component(InferenceComponentName=ic_name)
    assert ic_desc["InferenceComponentStatus"] != "InService", (
        f"expected the inference component to not yet be InService while its endpoint reads "
        f"{initial_status!r}, got {ic_desc['InferenceComponentStatus']!r}"
    )
    assert ic_desc["RuntimeConfig"]["CurrentCopyCount"] == 0, (
        f"expected zero deployed copies while the endpoint is not InService, got "
        f"{ic_desc['RuntimeConfig']['CurrentCopyCount']!r} of "
        f"{ic_desc['RuntimeConfig']['DesiredCopyCount']!r} desired"
    )
    _endpoint_status_in_window(sm, endpoint_name)

    # Wait for the endpoint to reach InService, then demand the withheld deployment.
    desc = _poll_until(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name),
        lambda d: d["EndpointStatus"] in ("InService", "Failed"),
        timeout_s=900,
        interval_s=15,
    )
    assert desc["EndpointStatus"] == "InService", (
        f"expected the endpoint to reach InService, got {desc['EndpointStatus']!r} "
        f"(FailureReason={desc.get('FailureReason')!r})"
    )

    ic_desc = _poll_until(
        lambda: sm.describe_inference_component(InferenceComponentName=ic_name),
        lambda d: d["InferenceComponentStatus"] in ("InService", "Failed"),
        timeout_s=300,
        interval_s=10,
    )
    assert ic_desc["InferenceComponentStatus"] == "InService", (
        f"expected the inference component to converge to InService once its endpoint did, "
        f"got {ic_desc['InferenceComponentStatus']!r} (FailureReason={ic_desc.get('FailureReason')!r})"
    )
    assert ic_desc["RuntimeConfig"]["CurrentCopyCount"] == ic_desc["RuntimeConfig"]["DesiredCopyCount"], (
        f"expected the deployed copy count to reach the desired count once InService, got "
        f"{ic_desc['RuntimeConfig']['CurrentCopyCount']!r} of "
        f"{ic_desc['RuntimeConfig']['DesiredCopyCount']!r} desired"
    )
    assert ic_desc["EndpointName"] == endpoint_name, (
        f"expected the inference component to stay bound to {endpoint_name!r}, "
        f"got {ic_desc['EndpointName']!r}"
    )

    sm.delete_inference_component(InferenceComponentName=ic_name)
    gone = _poll_until_client_error(
        lambda: sm.describe_inference_component(InferenceComponentName=ic_name),
        timeout_s=300,
        interval_s=5,
    )
    assert gone["Code"] == "ValidationException", (
        f"expected the deleted inference component to read ValidationException (SageMaker's "
        f"not-found code for this describe call), got {gone!r}"
    )
    expected_message = f'Could not find inference component "{create_resp["InferenceComponentArn"]}".'
    assert gone["Message"] == expected_message, (
        f"expected DescribeInferenceComponent's not-found message {expected_message!r}, "
        f"got {gone['Message']!r}"
    )


def _endpoint_status_in_window(sm, endpoint_name: str) -> str:
    status = sm.describe_endpoint(EndpointName=endpoint_name)["EndpointStatus"]
    assert status == "Creating", (
        f"expected the endpoint to read Creating around the in-window observation, got {status!r}"
    )
    return status


def _is_gone(exc: ClientError) -> bool:
    """SageMaker reports a missing endpoint, config or component as ValidationException 'Could not find'."""
    err = exc.response["Error"]
    return err["Code"] == "ResourceNotFound" or (
        err["Code"] == "ValidationException" and err.get("Message", "").startswith("Could not find")
    )


def _delete_ic_best_effort(sm, ic_name: str) -> None:
    try:
        sm.delete_inference_component(InferenceComponentName=ic_name)
    except ClientError as exc:
        if not _is_gone(exc):
            raise


def _delete_endpoint_best_effort(sm, endpoint_name: str) -> None:
    try:
        sm.delete_endpoint(EndpointName=endpoint_name)
    except ClientError as exc:
        if not _is_gone(exc):
            raise
    deadline = time.monotonic() + 300
    while True:
        try:
            sm.describe_endpoint(EndpointName=endpoint_name)
        except ClientError as exc:
            if _is_gone(exc):
                return
            raise
        if time.monotonic() >= deadline:
            raise TimeoutError(f"endpoint {endpoint_name} still describable 300s after its delete")
        time.sleep(2)


def _delete_endpoint_config_best_effort(sm, endpoint_config_name: str) -> None:
    try:
        sm.delete_endpoint_config(EndpointConfigName=endpoint_config_name)
    except ClientError as exc:
        if not _is_gone(exc):
            raise


def _create_endpoint_config_with_retry(sm, *, timeout_s=60.0, interval_s=5.0, **kwargs):
    """Retry the role-related ValidationException for a bounded window (IAM eventual consistency)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.create_endpoint_config(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code != "ValidationException" or "role" not in message.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


_ROLE_PROPAGATION_MARKERS = ("execution role", "cannot pull", "could not access model data")


def _create_inference_component_retry_role_propagation(sm, *, timeout_s=150.0, interval_s=5.0, **kwargs):
    """Retry CreateInferenceComponent only on the IAM-propagation rejections ('execution role
    ARN ... is invalid', 'cannot pull <image>', 'could not access model data')."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.create_inference_component(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            transient = code == "ValidationException" and any(m in message.lower() for m in _ROLE_PROPAGATION_MARKERS)
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until_client_error(fn, *, timeout_s: float, interval_s: float) -> dict:
    """Call ``fn`` until it raises a ClientError and return that error's ``Error`` dict; a call
    that keeps succeeding past the deadline is an AssertionError, never a falsy result."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            return exc.response["Error"]
        if time.monotonic() >= deadline:
            raise AssertionError(f"the call kept succeeding for {timeout_s}s; expected a ClientError")
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sm-exec-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="sim2real behavioral check: SageMaker endpoint execution role",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
    )
    # CreateInferenceComponent synchronously verifies the role can pull the container image and
    # read the model artifact, so the role needs real ECR and S3 read permissions on top of
    # SageMaker access.
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    )
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    )
    ctx.on_cleanup(lambda: _delete_role_best_effort(iam, role_name))
    return role_arn


def _delete_role_best_effort(iam, role_name: str) -> None:
    for policy_arn in (
        "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    ):
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


def _create_model_artifact(ctx) -> str:
    """CreateInferenceComponent synchronously fetches the model artifact, and ArtifactUrl must
    point to a single .tar.gz object (not a prefix), so a real bucket + object is required."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-ic-artifact-").lower()
    # S3's CreateBucket rejects an explicit LocationConstraint of us-east-1 (its implicit default).
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    key = "model.tar.gz"
    s3.put_object(Bucket=bucket, Key=key, Body=b"")
    ctx.on_cleanup(lambda: _delete_model_artifact_best_effort(s3, bucket, key))
    return f"s3://{bucket}/{key}"


def _delete_model_artifact_best_effort(s3, bucket: str, key: str) -> None:
    try:
        s3.delete_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
