"""sagemaker-batch-transform-and-realtime-endpoint-agree-on-every-row."""
from __future__ import annotations

import json
import math
import time
from urllib.parse import urlparse
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sagemaker-batch-transform-and-realtime-endpoint-agree-on-every-row"
GROUP = 'inference'
SERVICES = ['s3', 'sagemaker']

# The three inference rows, features only (no label column). Row order is the whole point: the
# transform output must line up with it.
_INFER_ROWS = ("0.5000,0.5000", "4.0000,5.0000", "9.5000,9.5000")
_INFER_KEY = "infer/probe.csv"

# AWS's own registry account for the built-in XGBoost algorithm image, one per region.
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
        Tags=[{"Key": "sim2real", "Value": "transform-agreement"}],
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
    # IAM propagation exposes no condition to poll; _create_training_job_with_retry retries the
    # resulting ValidationException.
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


def _stop_transform_if_running(sm: Any, job_name: str) -> None:
    """Stop a running transform job; transform jobs cannot be deleted, only stopped while running."""
    desc = sm.describe_transform_job(TransformJobName=job_name)
    if desc["TransformJobStatus"] in ("InProgress", "Stopping"):
        sm.stop_transform_job(TransformJobName=job_name)


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


def _wait_transform_terminal(sm: Any, job_name: str, *, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    desc: dict = {}
    while time.monotonic() < deadline:
        desc = sm.describe_transform_job(TransformJobName=job_name)
        if desc["TransformJobStatus"] in ("Completed", "Failed", "Stopped"):
            return desc
        time.sleep(5)
    raise AssertionError(
        f"transform job {job_name} never reached a terminal state within {timeout_s}s: "
        f"{desc.get('TransformJobStatus')!r}"
    )


def _delete_endpoint_confirmed(sm: Any, endpoint: str) -> None:
    """Delete the endpoint and poll until DescribeEndpoint no longer finds it."""
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


def _list_all_keys(s3: Any, bucket: str, prefix: str) -> list:
    keys, token = [], None
    while True:
        kw = {"Bucket": bucket, "Prefix": prefix}
        if token:
            kw["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kw)
        keys.extend(o["Key"] for o in resp.get("Contents", []))
        token = resp.get("NextContinuationToken")
        if not token:
            return sorted(keys)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """One trained model scores three rows identically via InvokeEndpoint and via Batch Transform,
    whose S3 output holds exactly one prediction per input row in input order.
    """
    image_uri = _algo_image(ctx)
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sm = ctx.client("sagemaker")
    smrt = ctx.client("sagemaker-runtime")
    train_timeout_s = 900
    deploy_timeout_s = 900
    transform_timeout_s = 900

    bucket = ctx.unique_name("sim2real-sm-inf-")
    _create_bucket(ctx, s3, bucket, "transform-agreement")
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=_training_csv())
    s3.put_object(
        Bucket=bucket, Key=_INFER_KEY,
        Body=("\n".join(_INFER_ROWS) + "\n").encode("utf-8"),
    )
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
        HyperParameters={"objective": "reg:linear", "num_round": "20"},
        Tags=[{"Key": "sim2real", "Value": "transform-agreement"}],
    )
    ctx.on_cleanup(lambda: _stop_training_if_running(sm, job_name))
    train_desc = _wait_training_terminal(sm, job_name, timeout_s=train_timeout_s)
    assert train_desc["TrainingJobStatus"] == "Completed", (
        f"prerequisite training job failed, so neither serving path has a model: "
        f"{train_desc.get('FailureReason')!r}"
    )
    artifact = train_desc["ModelArtifacts"]["S3ModelArtifacts"]
    assert urlparse(artifact).netloc == bucket, artifact

    model = ctx.unique_name("sim2real-sm-inf-model-")
    sm.create_model(
        ModelName=model,
        PrimaryContainer={"Image": image_uri, "ModelDataUrl": artifact},
        ExecutionRoleArn=role_arn,
        Tags=[{"Key": "sim2real", "Value": "transform-agreement"}],
    )
    ctx.on_cleanup(lambda: _quiet(lambda: sm.delete_model(ModelName=model)))

    # Both serving paths start together and are polled together, so the wall clock is their max.
    transform_job = ctx.unique_name("sim2real-sm-inf-xform-")
    sm.create_transform_job(
        TransformJobName=transform_job,
        ModelName=model,
        TransformInput={
            "DataSource": {"S3DataSource": {
                "S3DataType": "S3Prefix",
                "S3Uri": f"s3://{bucket}/infer/",
            }},
            "ContentType": "text/csv",
            "SplitType": "Line",
        },
        TransformOutput={
            "S3OutputPath": f"s3://{bucket}/transform/",
            "Accept": "text/csv",
            "AssembleWith": "Line",
        },
        TransformResources={"InstanceType": "ml.m5.large", "InstanceCount": 1},
        BatchStrategy="SingleRecord",
        Tags=[{"Key": "sim2real", "Value": "transform-agreement"}],
    )
    ctx.on_cleanup(lambda: _stop_transform_if_running(sm, transform_job))

    config = ctx.unique_name("sim2real-sm-inf-cfg-")
    sm.create_endpoint_config(
        EndpointConfigName=config,
        ProductionVariants=[{
            "VariantName": "AllTraffic",
            "ModelName": model,
            "ServerlessConfig": {"MemorySizeInMB": 2048, "MaxConcurrency": 1},
        }],
        Tags=[{"Key": "sim2real", "Value": "transform-agreement"}],
    )
    ctx.on_cleanup(lambda: _quiet(lambda: sm.delete_endpoint_config(EndpointConfigName=config)))

    endpoint = ctx.unique_name("sim2real-sm-inf-ep-")
    sm.create_endpoint(
        EndpointName=endpoint,
        EndpointConfigName=config,
        Tags=[{"Key": "sim2real", "Value": "transform-agreement"}],
    )
    ctx.on_cleanup(lambda: _delete_endpoint_confirmed(sm, endpoint))

    ep_desc = _wait_endpoint_terminal(sm, endpoint, timeout_s=deploy_timeout_s)
    assert ep_desc["EndpointStatus"] == "InService", (
        f"the real-time half never came up: {ep_desc.get('FailureReason')!r}"
    )

    # One row per request: the endpoint answers a multi-row request as one comma-separated line,
    # while the transform output has one prediction per line.
    def invoke_row(row: str) -> float:
        raw = smrt.invoke_endpoint(
            EndpointName=endpoint, ContentType="text/csv", Body=row
        )["Body"].read().decode("utf-8").strip()
        value = float(raw)
        assert math.isfinite(value), f"the endpoint scored {row!r} as {raw!r}"
        return value

    realtime = [invoke_row(row) for row in _INFER_ROWS]
    # Second pass over the SAME rows: this is what separates "the two paths agree" from "the
    # endpoint is nondeterministic and happened to match".
    realtime_again = [invoke_row(row) for row in _INFER_ROWS]
    assert realtime_again == realtime, (
        f"the endpoint is not deterministic for fixed inputs, so an agreement with the transform "
        f"output below would be meaningless: {realtime!r} then {realtime_again!r}"
    )

    xform_desc = _wait_transform_terminal(sm, transform_job, timeout_s=transform_timeout_s)
    assert xform_desc["TransformJobStatus"] == "Completed", (
        f"the batch half did not complete: {xform_desc.get('FailureReason')!r}"
    )

    output_keys = _list_all_keys(s3, bucket, "transform/")
    expected_key = f"transform/{_INFER_KEY.split('/')[-1]}.out"
    assert output_keys == [expected_key], (
        f"Batch Transform must write exactly one output object, named after its input object: "
        f"{output_keys!r}, expected [{expected_key!r}]"
    )
    output_raw = s3.get_object(Bucket=bucket, Key=expected_key)["Body"].read().decode("utf-8")
    lines = [line for line in output_raw.splitlines() if line.strip()]
    assert len(lines) == len(_INFER_ROWS), (
        f"Batch Transform with BatchStrategy SingleRecord and SplitType Line must emit exactly one "
        f"prediction per input row: got {len(lines)} for {len(_INFER_ROWS)} rows. Raw output was "
        f"{output_raw!r}"
    )
    batch = [float(line.strip()) for line in lines]

    # Two independent execution paths, same numbers, same order.
    assert batch == realtime, (
        f"the same model scored the same rows differently on its two serving paths -- batch "
        f"transform gave {batch!r} while the real-time endpoint gave {realtime!r} for rows "
        f"{list(_INFER_ROWS)!r}. Raw transform output: {output_raw!r}"
    )
    # Defensive: a model that learned a constant would satisfy the equality above vacuously.
    assert len(set(batch)) == len(batch), (
        f"all {len(batch)} input rows scored identically, so the agreement above proves nothing "
        f"about either path: {batch!r}"
    )
    assert batch[0] < batch[1] < batch[2], (
        f"the training labels increase strictly with both features and the three inference rows are "
        f"ordered, so the predictions must be too -- if they are not, the transform output is not "
        f"aligned with the input rows: {batch!r}"
    )

    # The batch job's own accounting corroborates that it processed this input.
    assert xform_desc["ModelName"] == model, xform_desc
    # TransformInput -> DataSource -> S3DataSource -> S3Uri: three levels, per the model.
    assert xform_desc["TransformInput"]["DataSource"]["S3DataSource"]["S3Uri"] == \
        f"s3://{bucket}/infer/", (
        f"the transform job must echo the prefix it was given: {xform_desc['TransformInput']!r}"
    )
    assert xform_desc["TransformInput"]["SplitType"] == "Line", (
        f"the split type decides the one-prediction-per-row framing asserted above: "
        f"{xform_desc['TransformInput']!r}"
    )
    assert xform_desc["BatchStrategy"] == "SingleRecord", xform_desc.get("BatchStrategy")
    assert xform_desc["TransformStartTime"] <= xform_desc["TransformEndTime"], (
        f"the transform job's timings are not ordered: "
        f"{xform_desc['TransformStartTime']!r} .. {xform_desc['TransformEndTime']!r}"
    )
    assert xform_desc["TransformEndTime"] >= train_desc["TrainingEndTime"], (
        f"the transform cannot have finished before the model it used finished training: "
        f"{xform_desc['TransformEndTime']!r} vs {train_desc['TrainingEndTime']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
