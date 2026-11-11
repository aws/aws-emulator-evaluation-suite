"""delete-web-function-cascades-tags-and-resource-policy."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-web-function-cascades-tags-and-resource-policy"
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


def _poll_until_error(fn, *, budget_s: float = 30.0, interval_s: float = 2.0):
    """(Code, Message) of the ClientError ``fn()`` eventually raises, within a budget."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        if time.monotonic() > deadline:
            raise AssertionError(f"still succeeding after {budget_s}s: {result!r}")
        time.sleep(interval_s)


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """Deleting a web function also destroys its resource policy and tags: neither
    survives as orphaned state readable through a stale ARN.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/
    """
    lw, function_name, function_arn = _create_role_bucket_and_function(ctx)

    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "sim2realBehavCascade", "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "lambda:InvokeFunctionUrl", "Resource": function_arn,
        }],
    })
    lw.put_resource_policy(resourceArn=function_arn, policy=policy)
    lw.tag_resource(resource=function_arn, tags={"sim2real-behav-cascade": "v1"})

    # Confirm both are actually attached before the delete, so the later absence means
    # something.
    attached = json.loads(lw.get_resource_policy(resourceArn=function_arn)["policy"])
    assert attached == json.loads(policy), f"attached policy {attached!r} != {json.loads(policy)!r}"
    assert lw.list_tags(resource=function_arn)["tags"] == {"sim2real-behav-cascade": "v1"}

    lw.delete_web_function(functionName=function_name)

    expected_message = f"The function {function_arn} does not exist."

    code, message = _poll_until_error(lambda: lw.get_resource_policy(resourceArn=function_arn))
    assert code == "ResourceNotFoundException", (
        f"GetResourcePolicy on a deleted function eventually gave {code}: {message!r}, "
        f"expected ResourceNotFoundException"
    )
    assert message == expected_message, (
        f"GetResourcePolicy on a deleted function said {message!r}, expected {expected_message!r} "
        f"-- a lingering 'does not have a policy' answer would mean the policy outlived the function"
    )

    code, message = _poll_until_error(lambda: lw.list_tags(resource=function_arn))
    assert code == "ResourceNotFoundException", (
        f"ListTags on a deleted function eventually gave {code}: {message!r}, "
        f"expected ResourceNotFoundException"
    )
    assert message == expected_message, (
        f"ListTags on a deleted function said {message!r}, expected {expected_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
