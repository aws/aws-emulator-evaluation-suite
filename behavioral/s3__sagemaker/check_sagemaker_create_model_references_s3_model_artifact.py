"""sagemaker-create-model-references-s3-model-artifact."""
from __future__ import annotations

import io
import json
import tarfile
from typing import Any

from behavioral_harness import tags

CHECK = "sagemaker-create-model-references-s3-model-artifact"
GROUP = "arn-resolution"
SERVICES = ["s3", "sagemaker"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """CreateModel accepts a ModelDataUrl pointing at a real S3 object and DescribeModel
    resolves it back verbatim, with the referenced object actually present and intact.
    """
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")

    bucket = _create_bucket(ctx)
    key = "model-artifacts/model.tar.gz"
    body = _build_model_tarball(b"sim2real-dummy-weights")
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    model_data_url = f"s3://{bucket}/{key}"

    role_arn = _create_role(ctx, [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }
    ])["arn"]

    image = f"{_xgboost_registry_account(ctx.region)}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-xgboost:1.7-1"
    model_name = ctx.unique_name("sim2real-sm-model-")

    def _create() -> None:
        sm.create_model(
            ModelName=model_name,
            PrimaryContainer={"Image": image, "ModelDataUrl": model_data_url},
            ExecutionRoleArn=role_arn,
            Tags=[{"Key": "sim2real", "Value": "s3-model-artifact"}],
        )

    _call_with_role_propagation_retry(_create)
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_name))

    desc = sm.describe_model(ModelName=model_name)
    assert desc["PrimaryContainer"]["ModelDataUrl"] == model_data_url
    assert desc["PrimaryContainer"]["Image"] == image

    names = [m["ModelName"] for m in sm.list_models(NameContains=model_name)["Models"]]
    assert model_name in names

    # The referenced artifact must actually exist and be byte-identical to what we uploaded --
    # a faithful emulator resolves the URL to real object content, not a stub.
    fetched = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert fetched == body


def _build_model_tarball(content: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = io.BytesIO(content)
        info = tarfile.TarInfo(name="model.bin")
        info.size = len(content)
        tar.addfile(info, data)
    return buf.getvalue()


def _xgboost_registry_account(region: str) -> str:
    # Per-region ECR registry account IDs that host the SageMaker-managed
    # "sagemaker-xgboost" framework/algorithm container images.
    accounts = {
        "us-east-1": "683313688378",
        "us-east-2": "257758044811",
        "us-west-1": "746614075791",
        "us-west-2": "246618743249",
        "ca-central-1": "341280168497",
        "eu-west-1": "141502667606",
        "eu-west-2": "764974769150",
        "eu-west-3": "659782779980",
        "eu-central-1": "492215442770",
        "eu-north-1": "669576153137",
        "ap-northeast-1": "354813040037",
        "ap-northeast-2": "366743142698",
        "ap-southeast-1": "121021644041",
        "ap-southeast-2": "783357654285",
        "ap-south-1": "720646828776",
        "sa-east-1": "737474898029",
    }
    return accounts.get(region, "683313688378")


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-s3-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "s3-model-artifact"}]})

    def _cleanup() -> None:
        contents = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if contents:
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in contents]})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_role(ctx: Any, policy_statements: list[dict[str, Any]]) -> dict[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "s3-model-artifact"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if policy_statements:
        policy_name = ctx.unique_name("sim2real-sm-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return {"arn": role_arn, "name": role_name}


def _call_with_role_propagation_retry(fn: Any, timeout_s: float = 90.0, interval_s: float = 5.0) -> Any:
    """IAM is eventually consistent: a role/policy created moments ago can transiently deny
    SageMaker's AssumeRole. Retry the dependent call itself, bounded, instead of sleeping blind."""
    import time

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - narrowed to known propagation signatures below
            msg = str(exc)
            if any(
                tok in msg
                for tok in (
                    "is not authorized",
                    "cannot be assumed",
                    "Unable to assume",
                    "Could not assume role",
                    "Could not access model data",
                )
            ):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
