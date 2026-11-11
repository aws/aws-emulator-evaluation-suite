"""custom-model-deployment-lifecycle-transitions."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "custom-model-deployment-lifecycle-transitions"
GROUP = "error-semantics"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCustomModel rejects a customer-owned S3 model source with "S3 URI not supported".

    The API requires an Amazon-managed bucket; the rejected model name never appears in
    ListCustomModels, and ListCustomModels answering first is the healthy-account control.
    """
    bedrock = ctx.client("bedrock")

    # Positive control: the account/credentials are healthy for Bedrock's model
    # control plane in general, so the refusal below isn't "everything is denied".
    bedrock.list_custom_models(maxResults=1)

    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="model/config.json", Body=b'{"fake": "artifact"}')
    role_arn = _create_bedrock_role(ctx, bucket)

    model_name = ctx.unique_name("sim2real-custmodel-")
    got = _error(
        lambda: bedrock.create_custom_model(
            modelName=model_name,
            modelSourceConfig={"s3DataSource": {"s3Uri": f"s3://{bucket}/model/"}},
            roleArn=role_arn,
        )
    )
    expected = ("ValidationException", "S3 URI not supported")
    assert got == expected, f"expected {expected!r}, got {got!r}"

    listed = bedrock.list_custom_models(nameContains=model_name)["modelSummaries"]
    assert listed == [], listed


def _error(fn):
    """The AWS error (code, message) fn raises. Raises AssertionError if fn SUCCEEDS: an
    acceptance where AWS refuses must never read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError("the call was ACCEPTED where a refusal was expected")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bedrock-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_bedrock_role(ctx, bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bedrock-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy)
    )

    def _cleanup():
        iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access")
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
