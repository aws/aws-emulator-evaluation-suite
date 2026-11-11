"""untag-resource-is-idempotent-for-a-key-that-was-never-set."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-is-idempotent-for-a-key-that-was-never-set"
GROUP = 'resource-policy-and-tags'
SERVICES = ['lambda-web']

_CODE_ZIP_B64 = (
    "UEsDBBQAAAAIAHyiW10K8JOSqgAAAOMAAAAIABwAaW5kZXguanNVVAkAA2wH4WpsB+FqdXgLAAEE6AMAAAToAwAA"
    "NY7BDoIwDIbvPEVvGwnigkeCFy7eNMoL4GjiIm64FaIR390O4qFJ+//9+lc7GwhuRANU4PE5Go9SxFmkZaIXN6Cf"
    "0LMf5Vx7bAkviyYlIxlzIYVqD58EYp8HamkMteuQoUKp8q8jHbDtmBO1s4SWNs17QJGBIHzRduhbY2Puuo62kyKY"
    "R8GJ/Wbw7org7tH/cq1f5b0JfEiyqzFEZspPx3MD8ww7pRQv/gBQSwECHgMUAAAACAB8oltdCvCTkqoAAADjAAAA"
    "CAAYAAAAAAABAAAAtIEAAAAAaW5kZXguanNVVAUAA2wH4Wp1eAsAAQToAwAABOgDAABQSwUGAAAAAAEAAQBOAAAA"
    "7AAAAAAA"
)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_role_bucket_and_function(ctx):
    """Create an execution role, a versioned code bucket and one Active web function."""
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    lw = ctx.client("lambda-web")

    role_name = ctx.unique_name("sim2real-behav-lw-role-")
    bucket_name = ctx.unique_name("sim2real-behav-lambdaweb-")
    function_name = ctx.unique_name("sim2real-behav-lw-fn-")

    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    s3.create_bucket(Bucket=bucket_name,
                      CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket_name), "NoSuchBucket"))
    s3.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowLambdaServiceGetObject", "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": ["s3:GetObject", "s3:GetObjectVersion"],
            "Resource": f"arn:aws:s3:::{bucket_name}/*",
            "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}},
        }],
    }))
    code_bytes = base64.b64decode(_CODE_ZIP_B64)
    put = s3.put_object(Bucket=bucket_name, Key="code.zip", Body=code_bytes)
    version_id = put["VersionId"]
    ctx.on_cleanup(_teardown(
        lambda: s3.delete_object(Bucket=bucket_name, Key="code.zip", VersionId=version_id),
        "NoSuchKey", "NoSuchVersion",
    ))

    deadline = time.monotonic() + 60
    create_kwargs = dict(
        functionName=function_name,
        revisionConfig={
            "buildConfig": {
                "codeConfig": {"s3Object": {"bucket": bucket_name, "key": "code.zip"}},
                "runtimeConfig": {"runtime": "nodejs24.x"},
            },
            "serviceConfig": {"executionRoleArn": role_arn},
        },
        endpointConfig={"endpointName": "ep", "endpointType": "HomeRegion", "authType": "IamAuth"},
    )
    while True:
        try:
            created = lw.create_web_function(**create_kwargs)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ValidationException" or time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(_teardown(
        lambda: lw.delete_web_function(functionName=function_name), "ResourceNotFoundException",
    ))
    return lw, function_name, created["functionArn"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource for a key the function was never tagged with succeeds as a no-op,
    and an existing tag survives that call untouched.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/
    """
    lw, function_name, function_arn = _create_role_bucket_and_function(ctx)

    lw.tag_resource(resource=function_arn, tags={"sim2real-behav-kept": "v1"})
    before = lw.list_tags(resource=function_arn)["tags"]
    assert before == {"sim2real-behav-kept": "v1"}, f"unexpected tags before untag: {before!r}"

    response = lw.untag_resource(resource=function_arn, tagKeys=["sim2real-behav-never-set"])
    status = response["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 204, f"UntagResource for a never-set key answered {status}, expected 204"

    after = lw.list_tags(resource=function_arn)["tags"]
    assert after == before, (
        f"UntagResource for a never-set key changed the tag set: {before!r} -> {after!r}"
    )

    lw.untag_resource(resource=function_arn, tagKeys=["sim2real-behav-kept"])
    cleared = lw.list_tags(resource=function_arn)["tags"]
    assert cleared == {}, f"removing the real key left {cleared!r}, expected empty"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
