"""sagemaker-endpoint-prediction-is-deterministic-and-ordered-in-its-input."""
from __future__ import annotations

import json
import math
import time
from urllib.parse import urlparse
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sagemaker-endpoint-prediction-is-deterministic-and-ordered-in-its-input"
GROUP = 'inference'
SERVICES = ['sagemaker']

# AWS-published ECR account that hosts the built-in XGBoost training/inference image, one per
# region -- not a quota or account setting, but the actual (region-pinned) location of the image.
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


def _monotone_training_csv(n_rows: int = 60) -> bytes:
    """label,f1,f2 with label == 2*f1 + 3*f2, exactly, on a grid.

    Generated in the check rather than uploaded as an opaque fixture so the relation the model is
    expected to learn is stated where the assertions can be read against it: the label increases
    strictly with each feature, so predictions must be ordered the same way. If the ordering
    assertion below ever fires, the first suspect is this fixture (too few rounds, too few rows),
    not the service.
    """
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
        Tags=[{"Key": "sim2real", "Value": "inference-determinism"}],
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
    """IAM propagation exposes no condition to poll, so the bound is here: retry the actual
    call that needs the role, on the specific error propagation delay produces, up to a deadline."""
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
    """Delete and CONFIRM the deletion progressed. ctx.on_cleanup swallows exceptions, so a
    fire-and-forget delete_endpoint would leak a billable hosting resource while the check passed."""
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed endpoint scores as a pure function of its input: a repeated row returns
    byte-identical bodies, an increasing feature sweep never decreases and rises end to end, and a
    two-row request returns two in-order predictions, each equal to that row scored alone."""
    image_uri = _algo_image(ctx)
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sm = ctx.client("sagemaker")
    smrt = ctx.client("sagemaker-runtime")
    train_timeout_s = 900
    deploy_timeout_s = 900

    bucket = ctx.unique_name("sim2real-sm-inf-")
    _create_bucket(ctx, s3, bucket, "inference-determinism")
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=_monotone_training_csv())
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
        Tags=[{"Key": "sim2real", "Value": "inference-determinism"}],
    )
    ctx.on_cleanup(lambda: _stop_training_if_running(sm, job_name))
    train_desc = _wait_training_terminal(sm, job_name, timeout_s=train_timeout_s)
    assert train_desc["TrainingJobStatus"] == "Completed", (
        f"prerequisite training job failed, so there is nothing to deploy: "
        f"{train_desc.get('FailureReason')!r}"
    )
    artifact = train_desc["ModelArtifacts"]["S3ModelArtifacts"]
    assert urlparse(artifact).netloc == bucket, artifact

    model = ctx.unique_name("sim2real-sm-inf-model-")
    sm.create_model(
        ModelName=model,
        PrimaryContainer={"Image": image_uri, "ModelDataUrl": artifact},
        ExecutionRoleArn=role_arn,
        Tags=[{"Key": "sim2real", "Value": "inference-determinism"}],
    )
    ctx.on_cleanup(lambda: _quiet(lambda: sm.delete_model(ModelName=model)))

    config = ctx.unique_name("sim2real-sm-inf-cfg-")
    sm.create_endpoint_config(
        EndpointConfigName=config,
        ProductionVariants=[{
            "VariantName": "AllTraffic",
            "ModelName": model,
            # MEASURED: a serverless variant is the only affordable real-time hosting here -- it
            # reaches InService in ~100s against 5-15 minutes for an instance-backed variant, and
            # there is no instance to strand if this check dies.
            "ServerlessConfig": {"MemorySizeInMB": 2048, "MaxConcurrency": 1},
        }],
        Tags=[{"Key": "sim2real", "Value": "inference-determinism"}],
    )
    ctx.on_cleanup(lambda: _quiet(lambda: sm.delete_endpoint_config(EndpointConfigName=config)))

    endpoint = ctx.unique_name("sim2real-sm-inf-ep-")
    sm.create_endpoint(
        EndpointName=endpoint,
        EndpointConfigName=config,
        Tags=[{"Key": "sim2real", "Value": "inference-determinism"}],
    )
    ctx.on_cleanup(lambda: _delete_endpoint_confirmed(sm, endpoint))

    ep_desc = _wait_endpoint_terminal(sm, endpoint, timeout_s=deploy_timeout_s)
    assert ep_desc["EndpointStatus"] == "InService", (
        f"the endpoint never came up, so no inference assertion below is reachable: "
        f"{ep_desc.get('FailureReason')!r}"
    )

    def invoke(body: str) -> dict:
        return smrt.invoke_endpoint(
            EndpointName=endpoint, ContentType="text/csv", Body=body
        )

    # --- Determinism: the same input, five times, byte for byte. ---
    first = invoke("4.0,5.0")
    first_raw = first["Body"].read()
    assert first["InvokedProductionVariant"] == "AllTraffic", (
        f"the only variant configured must be the one that served: "
        f"{first.get('InvokedProductionVariant')!r}"
    )
    assert first["ContentType"].startswith("text/csv"), (
        f"the container must answer in the content type it advertises: {first['ContentType']!r}"
    )
    repeats = [first_raw] + [invoke("4.0,5.0")["Body"].read() for _ in range(4)]
    assert len(set(repeats)) == 1, (
        f"the same input produced {len(set(repeats))} distinct response bodies, so the endpoint is "
        f"not a deterministic function of its input: {sorted(set(repeats))!r}"
    )

    # --- Ordering: a sweep the model was trained to rank. ---
    sweep_inputs = [0.5 + i for i in range(10)]
    sweep = []
    for value in sweep_inputs:
        raw = invoke(f"{value:.4f},{value:.4f}")["Body"].read().decode("utf-8").strip()
        parsed = float(raw)
        assert math.isfinite(parsed), (
            f"the endpoint returned a non-finite prediction for input {value!r}: {raw!r}"
        )
        sweep.append(parsed)
    assert all(a <= b for a, b in zip(sweep, sweep[1:])), (
        f"the training labels increase strictly with both features, so predictions must never "
        f"decrease across this sweep: inputs={sweep_inputs!r} predictions={sweep!r}"
    )
    assert sweep[-1] - sweep[0] > 1e-3, (
        f"the model is effectively constant across the whole input range, so the ordering "
        f"assertion above proves nothing: {sweep!r}"
    )

    # --- Per-row independence: two rows in, two predictions out, in input order. ---
    low_alone = float(invoke("0.5000,0.5000")["Body"].read().decode("utf-8").strip())
    high_alone = float(invoke("9.5000,9.5000")["Body"].read().decode("utf-8").strip())
    batched_raw = invoke("0.5000,0.5000\n9.5000,9.5000")["Body"].read().decode("utf-8").strip()
    # A multi-row CSV request returns ONE line of comma-separated predictions, not one line per
    # row, so the separator is asserted rather than assumed.
    assert "\n" not in batched_raw, (
        f"a batched response is a single comma-separated line, so a newline here means the "
        f"container's response framing changed: {batched_raw!r}"
    )
    batched = [float(field) for field in batched_raw.split(",") if field]
    assert len(batched) == 2, (
        f"a two-row request must return exactly one prediction per row: {batched_raw!r}"
    )
    assert batched == [low_alone, high_alone], (
        f"a batched request must return each row's own prediction in INPUT ORDER: got {batched!r}, "
        f"expected [{low_alone!r}, {high_alone!r}] from the same two rows sent separately"
    )
    assert low_alone < high_alone, (
        f"the two ends of the input range must not score the same: {low_alone!r} vs {high_alone!r}"
    )

    # --- What the endpoint says it is running. ---
    variants = ep_desc["ProductionVariants"]
    assert len(variants) == 1, f"exactly one variant was configured: {variants!r}"
    variant = variants[0]
    assert variant["CurrentWeight"] == 1.0 and variant["DesiredWeight"] == 1.0, variant
    assert variant["CurrentInstanceCount"] == 0, (
        f"a serverless variant provisions no instances: "
        f"CurrentInstanceCount={variant['CurrentInstanceCount']!r}"
    )
    assert variant["CurrentServerlessConfig"] == {"MemorySizeInMB": 2048, "MaxConcurrency": 1}, (
        f"the serving variant must report the serverless configuration it was given: "
        f"{variant.get('CurrentServerlessConfig')!r}"
    )
    deployed = variant["DeployedImages"][0]
    assert deployed["SpecifiedImage"] == image_uri, (
        f"the endpoint must echo the image it was told to run: {deployed['SpecifiedImage']!r}"
    )
    assert deployed["ResolvedImage"].startswith(image_uri.rsplit(":", 1)[0] + "@sha256:"), (
        f"the endpoint must record the immutable DIGEST it actually pulled, not just the mutable "
        f"tag it was given: {deployed['ResolvedImage']!r} for specified "
        f"{deployed['SpecifiedImage']!r}"
    )
    assert deployed["ResolutionTime"] >= train_desc["TrainingEndTime"], (
        f"the image cannot have been resolved before the model it serves finished training: "
        f"resolved={deployed['ResolutionTime']!r} trained={train_desc['TrainingEndTime']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
