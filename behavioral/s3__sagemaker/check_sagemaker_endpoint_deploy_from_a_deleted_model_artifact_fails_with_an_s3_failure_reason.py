"""sagemaker-endpoint-deploy-from-a-deleted-model-artifact-fails-with-an-s3-failure-reason."""
from __future__ import annotations

import json
import math
import time
from urllib.parse import urlparse
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sagemaker-endpoint-deploy-from-a-deleted-model-artifact-fails-with-an-s3-failure-reason"
GROUP = 'overly-permissive'
SERVICES = ['s3', 'sagemaker']

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
        Tags=[{"Key": "sim2real", "Value": "deleted-artifact"}],
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


def _deploy(ctx: Any, sm: Any, image_uri: str, role_arn: str, model_data_url: str,
            label: str) -> tuple[str, str]:
    """Create a model, an endpoint config and an endpoint, registering each teardown as it goes.

    Returns (model_name, endpoint_name) without waiting, so both deployments overlap in time.
    """
    model = ctx.unique_name(f"sim2real-sm-inf-{label}-model-")
    sm.create_model(
        ModelName=model,
        PrimaryContainer={"Image": image_uri, "ModelDataUrl": model_data_url},
        ExecutionRoleArn=role_arn,
        Tags=[{"Key": "sim2real", "Value": "deleted-artifact"}],
    )
    ctx.on_cleanup(lambda: _quiet(lambda: sm.delete_model(ModelName=model)))

    config = ctx.unique_name(f"sim2real-sm-inf-{label}-cfg-")
    sm.create_endpoint_config(
        EndpointConfigName=config,
        ProductionVariants=[{
            "VariantName": "AllTraffic",
            "ModelName": model,
            # Serverless, not an instance-backed variant: hosting reaches a terminal state in
            # ~100s instead of 5-15 minutes, and there is no instance to strand.
            "ServerlessConfig": {"MemorySizeInMB": 2048, "MaxConcurrency": 1},
        }],
        Tags=[{"Key": "sim2real", "Value": "deleted-artifact"}],
    )
    ctx.on_cleanup(lambda: _quiet(lambda: sm.delete_endpoint_config(EndpointConfigName=config)))

    endpoint = ctx.unique_name(f"sim2real-sm-inf-{label}-ep-")
    sm.create_endpoint(
        EndpointName=endpoint,
        EndpointConfigName=config,
        Tags=[{"Key": "sim2real", "Value": "deleted-artifact"}],
    )
    # Registered IMMEDIATELY after the create, before any assertion, and it CONFIRMS the delete:
    # a Failed endpoint still exists and still bills nothing only once it is gone, and
    # ctx.on_cleanup swallows exceptions, so an unverified delete would leak silently.
    ctx.on_cleanup(lambda: _delete_endpoint_confirmed(sm, endpoint))
    return model, endpoint


def _delete_endpoint_confirmed(sm: Any, endpoint: str) -> None:
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


def _wait_both_endpoints(sm: Any, names: list, *, timeout_s: float) -> dict:
    """Poll several endpoints together until each reaches a terminal state."""
    deadline = time.monotonic() + timeout_s
    done: dict = {}
    while time.monotonic() < deadline:
        for name in names:
            if name in done:
                continue
            desc = sm.describe_endpoint(EndpointName=name)
            if desc["EndpointStatus"] in ("InService", "Failed"):
                done[name] = desc
        if len(done) == len(names):
            return done
        time.sleep(5)
    raise AssertionError(
        f"endpoints did not all reach a terminal state within {timeout_s}s; "
        f"terminal so far: { {k: v['EndpointStatus'] for k, v in done.items()} }"
    )


def _head_error(s3: Any, bucket: str, key: str) -> tuple[str, str]:
    """The (code, message) HeadObject raises; raises AssertionError when the object exists."""
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"HeadObject on s3://{bucket}/{key} succeeded, so the object still exists")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateModel accepts an S3 artifact that is then deleted; the endpoint fails at deploy time.
    Its FailureReason names the exact bucket and key, while an endpoint over a byte-identical copy
    reaches InService and returns a finite prediction.
    """
    image_uri = _algo_image(ctx)
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sm = ctx.client("sagemaker")
    smrt = ctx.client("sagemaker-runtime")
    train_timeout_s = 900
    deploy_timeout_s = 900

    bucket = ctx.unique_name("sim2real-sm-inf-")
    _create_bucket(ctx, s3, bucket, "deleted-artifact")
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
        Tags=[{"Key": "sim2real", "Value": "deleted-artifact"}],
    )
    ctx.on_cleanup(lambda: _stop_training_if_running(sm, job_name))
    train_desc = _wait_training_terminal(sm, job_name, timeout_s=train_timeout_s)
    assert train_desc["TrainingJobStatus"] == "Completed", (
        f"prerequisite training job failed, so there is no artifact to delete: "
        f"{train_desc.get('FailureReason')!r}"
    )

    artifact_uri = train_desc["ModelArtifacts"]["S3ModelArtifacts"]
    parsed = urlparse(artifact_uri)
    assert parsed.scheme == "s3" and parsed.netloc == bucket, artifact_uri
    doomed_key = parsed.path.lstrip("/")
    intact_key = "intact-copy/model.tar.gz"
    s3.copy_object(
        Bucket=bucket, Key=intact_key,
        CopySource={"Bucket": bucket, "Key": doomed_key},
    )
    # Compared by bytes, not ETag: CopyObject within one bucket can yield a different ETag for
    # identical content, and the artifact is only a few KB.
    doomed_bytes = s3.get_object(Bucket=bucket, Key=doomed_key)["Body"].read()
    intact_bytes = s3.get_object(Bucket=bucket, Key=intact_key)["Body"].read()
    assert doomed_bytes == intact_bytes, (
        f"the two copies must be byte-identical, or the two deployments below differ in more than "
        f"the one thing under test: {len(doomed_bytes)} bytes vs {len(intact_bytes)} bytes"
    )
    assert len(doomed_bytes) > 0, (
        f"the training job produced a zero-byte artifact, so neither deployment would be "
        f"meaningful: {doomed_key!r}"
    )

    # The finding: CreateModel does not resolve the object, so BOTH models are accepted.
    broken_model, broken_endpoint_name = _deploy(
        ctx, sm, image_uri, role_arn, f"s3://{bucket}/{doomed_key}", "broken"
    )
    intact_model, intact_endpoint_name = _deploy(
        ctx, sm, image_uri, role_arn, f"s3://{bucket}/{intact_key}", "intact"
    )

    # Break exactly one thing: the object one of the two models points at stops existing.
    s3.delete_object(Bucket=bucket, Key=doomed_key)
    assert _head_error(s3, bucket, doomed_key) == ("404", "Not Found"), (
        "the artifact under test must really be gone before the deployments resolve it"
    )
    # The sibling copy must survive, or the control proves nothing: HeadObject raises if it is gone.
    s3.head_object(Bucket=bucket, Key=intact_key)

    described_broken = sm.describe_model(ModelName=broken_model)
    assert described_broken["PrimaryContainer"]["ModelDataUrl"] == \
        f"s3://{bucket}/{doomed_key}", (
        f"DescribeModel must still echo the now-dangling URI -- the control plane never resolves "
        f"it: {described_broken['PrimaryContainer']['ModelDataUrl']!r}"
    )

    terminal = _wait_both_endpoints(
        sm, [broken_endpoint_name, intact_endpoint_name], timeout_s=deploy_timeout_s
    )
    broken = terminal[broken_endpoint_name]
    intact = terminal[intact_endpoint_name]

    # Positive control first, because it is what makes the negative attributable.
    assert intact["EndpointStatus"] == "InService", (
        f"positive control: an endpoint over a byte-identical artifact at a LIVE key must deploy, "
        f"else the negative below is explained by hosting being broken rather than by the missing "
        f"object: {intact.get('FailureReason')!r}"
    )
    response = smrt.invoke_endpoint(
        EndpointName=intact_endpoint_name, ContentType="text/csv", Body="4.0,5.0"
    )
    prediction_text = response["Body"].read().decode("utf-8").strip()
    prediction = float(prediction_text.splitlines()[0])
    assert response["InvokedProductionVariant"] == "AllTraffic", response
    assert math.isfinite(prediction), (
        f"positive control: the control endpoint must return a finite number, so the container "
        f"demonstrably loaded and scored the artifact: {prediction_text!r}"
    )

    assert broken["EndpointStatus"] == "Failed", (
        f"an endpoint whose model artifact was deleted must fail to deploy rather than come up "
        f"serving something: {broken['EndpointStatus']!r}"
    )
    assert broken.get("FailureReason") == (
        f"Failed to download model data(bucket: {bucket}, key: {doomed_key}). Please ensure that "
        f"there is an object located at the URL and that the role passed to CreateModel has "
        f"permissions to download the model."
    ), (
        f"the FailureReason must attribute the failure to the download of the exact deleted key: "
        f"{broken.get('FailureReason')!r}"
    )
    assert not intact.get("FailureReason"), (
        f"positive control: the healthy endpoint must carry no FailureReason: "
        f"{intact.get('FailureReason')!r}"
    )
    # The control model still points where it was told to, so the two differ only in the key.
    described_intact = sm.describe_model(ModelName=intact_model)
    assert described_intact["PrimaryContainer"]["ModelDataUrl"] == \
        f"s3://{bucket}/{intact_key}", described_intact
    assert described_intact["PrimaryContainer"]["Image"] == \
        described_broken["PrimaryContainer"]["Image"], (
        f"the two models must share the same image, or the deployments differ in more than the "
        f"artifact key: {described_intact['PrimaryContainer']['Image']!r} vs "
        f"{described_broken['PrimaryContainer']['Image']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
