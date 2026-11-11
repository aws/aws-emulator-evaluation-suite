"""get-resource-policy-revision-id-is-stable-until-the-next-mutation."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resource-policy-revision-id-is-stable-until-the-next-mutation"
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


def _policy(sid: str, function_arn: str) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Sid": sid, "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                        "Action": "lambda:InvokeFunctionUrl", "Resource": function_arn}],
    })


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A policy's revision id is a real change token, not a per-request nonce: repeated
    GetResourcePolicy reads with no mutation between them answer the same id, and it
    changes only when PutResourcePolicy actually mutates the policy.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/
    """
    lw, function_name, function_arn = _create_role_bucket_and_function(ctx)

    rev1 = lw.put_resource_policy(resourceArn=function_arn, policy=_policy("v1", function_arn))["revisionId"]

    read_a = lw.get_resource_policy(resourceArn=function_arn)["revisionId"]
    read_b = lw.get_resource_policy(resourceArn=function_arn)["revisionId"]
    assert read_a == rev1 == read_b, (
        f"two unmutated reads returned {read_a!r} and {read_b!r}, expected both to equal {rev1!r}"
    )

    rev2 = lw.put_resource_policy(
        resourceArn=function_arn, policy=_policy("v2", function_arn), revisionId=rev1
    )["revisionId"]
    assert rev2 != rev1, "revision id did not change after a real mutation"

    read_c = lw.get_resource_policy(resourceArn=function_arn)["revisionId"]
    assert read_c == rev2, f"read after mutation returned {read_c!r}, expected the new id {rev2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
