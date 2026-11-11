"""sagemaker-invoke-with-an-unsupported-content-type-rejected-by-the-model-container."""
from __future__ import annotations

import json
import math
import time
from urllib.parse import urlparse
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sagemaker-invoke-with-an-unsupported-content-type-rejected-by-the-model-container"
GROUP = 'overly-permissive'
SERVICES = ['sagemaker']

# A content type the XGBoost serving container does not accept, carrying a token that appears
# nowhere else, so the refusal can be proven to be ABOUT this request rather than a generic string.
_UNSUPPORTED_CONTENT_TYPE = "application/x-unsupported-by-xgboost"
_VALID_BODY = "4.0,5.0"

# Region-pinned: AWS publishes the built-in XGBoost algorithm image to a different ECR
# registry account in each region; this is that fixed mapping, not a configurable value.
_XGBOOST_REGISTRY_ACCOUNTS = {
    "us-east-1": "811284229777",
    "us-east-2": "825641698319",
    "us-west-1": "632365934929",
    "us-west-2": "433757028032",
    "eu-west-1": "685385470294",
    "eu-central-1": "813361260812",
    "ap-northeast-1": "501404015308",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "544295431143",
    "ca-central-1": "469771592824",
}



def _quiet(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _algo_image(ctx: Any) -> str:

    account = _XGBOOST_REGISTRY_ACCOUNTS.get(ctx.region)
    if account is None:
        raise AssertionError(
            f"no SageMaker built-in XGBoost registry account is mapped for region "
            f"{ctx.region!r} in this check -- add it to close the gap"
        )
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/xgboost:1"


def _create_bucket(ctx: Any, s3: Any, bucket: str, scenario: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": scenario}]}
    )


def _delete_bucket(s3: Any, bucket: str) -> None:
    try:
        while True:
            resp = s3.list_objects_v2(Bucket=bucket)
            contents = resp.get("Contents", [])
            if not contents:
                break
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in contents]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _training_csv(n_rows: int = 60) -> bytes:
    lines = []
    for i in range(n_rows):
        f1 = (i % 10) + 0.5
        f2 = ((i * 3) % 10) + 0.5
        lines.append(f"{2.0 * f1 + 3.0 * f2:.4f},{f1:.4f},{f2:.4f}")
    return "\n".join(lines).encode("utf-8")


def _create_execution_role(ctx: Any, iam: Any, role_name: str, bucket: str) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "model-error"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="bucket-scoped",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }]}),
    )
    # IAM propagation exposes no condition to poll; the bounded retry in
    # _create_training_job_with_retry below is what makes this correct, so no sleep here.
    return arn


def _delete_role(iam: Any, role_name: str) -> None:
    for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    iam.delete_role(RoleName=role_name)


def _create_training_job_with_retry(sm: Any, *, timeout_s: float = 90.0, **kwargs) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.create_training_job(**kwargs)
            return
        except ClientError as exc:
            err = exc.response["Error"]
            msg = (err.get("Message") or "").lower()
            if err.get("Code") == "ValidationException" \
                    and ("assume role" in msg or "not authorized" in msg) \
                    and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _wait_training_terminal(sm: Any, job_name: str, *, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    desc: dict = {}
    while time.monotonic() < deadline:
        desc = sm.describe_training_job(TrainingJobName=job_name)
        if desc["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"):
            return desc
        time.sleep(5)
    raise AssertionError(
        f"training job {job_name} never reached a terminal state within {timeout_s}s: "
        f"secondary={desc.get('SecondaryStatus')!r}"
    )


def _stop_training_if_running(sm: Any, job_name: str) -> None:
    desc = sm.describe_training_job(TrainingJobName=job_name)
    if desc["TrainingJobStatus"] in ("InProgress", "Stopping"):
        sm.stop_training_job(TrainingJobName=job_name)


def _wait_endpoint_terminal(sm: Any, endpoint: str, *, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    desc: dict = {}
    while time.monotonic() < deadline:
        desc = sm.describe_endpoint(EndpointName=endpoint)
        if desc["EndpointStatus"] in ("InService", "Failed"):
            return desc
        time.sleep(5)
    raise AssertionError(
        f"endpoint {endpoint} never reached a terminal state within {timeout_s}s: "
        f"{desc.get('EndpointStatus')!r}"
    )


def _delete_endpoint_confirmed(sm: Any, endpoint: str) -> None:
    """Delete and CONFIRM. ctx.on_cleanup swallows exceptions, so an unverified delete_endpoint
    would leak a billable hosting resource while this check reported a pass."""
    sm.delete_endpoint(EndpointName=endpoint)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            sm.describe_endpoint(EndpointName=endpoint)
        except ClientError as exc:
            if exc.response["Error"].get("Code") in ("ValidationException", "ResourceNotFound"):
                return
            raise
        time.sleep(5)
    raise AssertionError(f"endpoint {endpoint} still exists 300s after DeleteEndpoint")


def _invoke_error(smrt: Any, **kwargs) -> dict:
    """The full botocore error response for an InvokeEndpoint expected to fail.

    Raises if the call SUCCEEDS -- an emulator that accepts input real AWS refuses is the strongest
    signal available here, and returning a falsy sentinel would turn it into an error-code mismatch
    that reads like a naming difference.
    """
    try:
        response = smrt.invoke_endpoint(**kwargs)
    except ClientError as exc:
        return exc.response
    raise AssertionError(
        f"InvokeEndpoint with ContentType={kwargs.get('ContentType')!r} SUCCEEDED and returned "
        f"{response['Body'].read()!r}; the model container must refuse a content type it does not "
        f"support rather than scoring the payload anyway"
    )


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """An unsupported ContentType on the same valid bytes is refused by the container as ModelError
    (HTTP 424) carrying its own 415 and supported types, wrapped and unwrapped messages differing;
    the endpoint stays InService and the baseline request returns the identical prediction.
    """
    image_uri = _algo_image(ctx)
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sm = ctx.client("sagemaker")
    smrt = ctx.client("sagemaker-runtime")
    train_timeout_s = 900
    deploy_timeout_s = 900

    bucket = ctx.unique_name("sim2real-sm-inf-")
    _create_bucket(ctx, s3, bucket, "model-error")
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=_training_csv())
    role_arn = _create_execution_role(
        ctx, iam, ctx.unique_name("sim2real-sm-inf-role-"), bucket
    )

    job_name = ctx.unique_name("sim2real-sm-inf-job-")
    _create_training_job_with_retry(
        sm,
        TrainingJobName=job_name,
        AlgorithmSpecification={"TrainingImage": image_uri, "TrainingInputMode": "File"},
        RoleArn=role_arn,
        InputDataConfig=[{
            "ChannelName": "train",
            "ContentType": "text/csv",
            "DataSource": {"S3DataSource": {
                "S3DataType": "S3Prefix",
                "S3Uri": f"s3://{bucket}/train/",
                "S3DataDistributionType": "FullyReplicated",
            }},
        }],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 900},
        HyperParameters={"objective": "reg:linear", "num_round": "15"},
        Tags=[{"Key": "sim2real", "Value": "model-error"}],
    )
    ctx.on_cleanup(lambda: _stop_training_if_running(sm, job_name))
    train_desc = _wait_training_terminal(sm, job_name, timeout_s=train_timeout_s)
    assert train_desc["TrainingJobStatus"] == "Completed", (
        f"prerequisite training job failed, so there is no container to interrogate: "
        f"{train_desc.get('FailureReason')!r}"
    )
    artifact = train_desc["ModelArtifacts"]["S3ModelArtifacts"]
    assert urlparse(artifact).netloc == bucket, artifact

    model = ctx.unique_name("sim2real-sm-inf-model-")
    sm.create_model(
        ModelName=model,
        PrimaryContainer={"Image": image_uri, "ModelDataUrl": artifact},
        ExecutionRoleArn=role_arn,
        Tags=[{"Key": "sim2real", "Value": "model-error"}],
    )
    ctx.on_cleanup(lambda: _quiet(lambda: sm.delete_model(ModelName=model)))

    config = ctx.unique_name("sim2real-sm-inf-cfg-")
    sm.create_endpoint_config(
        EndpointConfigName=config,
        ProductionVariants=[{
            "VariantName": "AllTraffic",
            "ModelName": model,
            "ServerlessConfig": {"MemorySizeInMB": 2048, "MaxConcurrency": 1},
        }],
        Tags=[{"Key": "sim2real", "Value": "model-error"}],
    )
    ctx.on_cleanup(lambda: _quiet(lambda: sm.delete_endpoint_config(EndpointConfigName=config)))

    endpoint = ctx.unique_name("sim2real-sm-inf-ep-")
    sm.create_endpoint(
        EndpointName=endpoint,
        EndpointConfigName=config,
        Tags=[{"Key": "sim2real", "Value": "model-error"}],
    )
    ctx.on_cleanup(lambda: _delete_endpoint_confirmed(sm, endpoint))
    ep_desc = _wait_endpoint_terminal(sm, endpoint, timeout_s=deploy_timeout_s)
    assert ep_desc["EndpointStatus"] == "InService", (
        f"the endpoint never came up, so nothing below would be attributable to the content type: "
        f"{ep_desc.get('FailureReason')!r}"
    )

    # --- The barrier: the endpoint demonstrably serves this exact body, so the later refusal
    # cannot be a malformed payload or an endpoint that is not ready. ---
    baseline = smrt.invoke_endpoint(
        EndpointName=endpoint, ContentType="text/csv", Body=_VALID_BODY
    )
    baseline_raw = baseline["Body"].read()
    baseline_prediction = float(baseline_raw.decode("utf-8").strip().splitlines()[0])
    assert math.isfinite(baseline_prediction), (
        f"the endpoint must serve a real prediction before anything is broken, or the refusal "
        f"below is not attributable to the content type: {baseline_raw!r}"
    )

    # --- Break exactly one thing: the ContentType header. Same endpoint, same bytes. ---
    error_response = _invoke_error(
        smrt,
        EndpointName=endpoint,
        ContentType=_UNSUPPORTED_CONTENT_TYPE,
        Body=_VALID_BODY,
    )
    code = error_response["Error"]["Code"]
    message = error_response["Error"]["Message"]
    status = error_response["ResponseMetadata"]["HTTPStatusCode"]

    assert code == "ModelError", (
        f"a refusal produced inside the model container must surface as ModelError, not {code!r}: "
        f"{message!r}"
    )
    assert status == 424, (
        f"ModelError is passed through as HTTP 424 Failed Dependency -- the status that says the "
        f"failure was the dependency's, not the caller's: got {status}"
    )
    # The container's own text names the content type asked for and the ones it accepts;
    # SageMaker wraps it with the container's HTTP status (415) and the endpoint's log group.
    expected_original = (
        f"Content-type {_UNSUPPORTED_CONTENT_TYPE} not supported. "
        f"Supported content-type is text/csv, text/libsvm"
    )
    expected_message = (
        f"Received client error (415) from model with message \"{expected_original}\". "
        f"See https://{ctx.region}.console.aws.amazon.com/cloudwatch/home?region={ctx.region}"
        f"#logEventViewer:group=/aws/sagemaker/Endpoints/{endpoint} in account {ctx.account} "
        f"for more information."
    )
    assert message == expected_message, (
        f"the message must carry the CONTAINER's own HTTP status and text, wrapped by SageMaker: "
        f"expected {expected_message!r}, got {message!r}"
    )
    # The two fields that carry the container's response UNWRAPPED. Modelled, not guessed: the
    # botocore response for this error is exactly
    # ['Error', 'Message', 'OriginalMessage', 'OriginalStatusCode', 'ResponseMetadata'].
    assert error_response["OriginalStatusCode"] == 415, (
        f"OriginalStatusCode must be the status the CONTAINER returned (415 Unsupported Media "
        f"Type), distinct from the 424 SageMaker wraps it in: "
        f"{error_response.get('OriginalStatusCode')!r}"
    )
    original = error_response["OriginalMessage"]
    assert original == expected_original, (
        f"OriginalMessage must be the container's own text about this request: "
        f"expected {expected_original!r}, got {original!r}"
    )
    assert original != message, (
        f"OriginalMessage is the container's raw text and Message is SageMaker's wrapping of it; "
        f"if they are identical the passthrough has collapsed: {original!r}"
    )

    # --- Effect absent: the endpoint is untouched. ---
    after = sm.describe_endpoint(EndpointName=endpoint)
    assert after["EndpointStatus"] == "InService", (
        f"a request the container refused must not wedge the endpoint: "
        f"{after['EndpointStatus']!r}"
    )
    assert not after.get("FailureReason"), (
        f"a refused inference request is not an endpoint failure: {after.get('FailureReason')!r}"
    )
    assert after["EndpointConfigName"] == config, after

    # --- Positive control: the same request that worked still works, byte for byte. ---
    control = smrt.invoke_endpoint(
        EndpointName=endpoint, ContentType="text/csv", Body=_VALID_BODY
    )
    control_raw = control["Body"].read()
    assert control_raw == baseline_raw, (
        f"positive control: after the refusal the endpoint must serve the identical prediction for "
        f"the identical request; the refused call changed the container's behaviour: "
        f"{baseline_raw!r} then {control_raw!r}"
    )
    assert control["InvokedProductionVariant"] == "AllTraffic", control


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
