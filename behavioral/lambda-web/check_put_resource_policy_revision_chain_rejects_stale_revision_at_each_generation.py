"""put-resource-policy-revision-chain-rejects-stale-revision-at-each-generation."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-revision-chain-rejects-stale-revision-at-each-generation"
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


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A policy revision id is a true optimistic-concurrency token across the whole chain:
    each PutResourcePolicy issues a fresh one, and a revision id from any earlier
    generation -- not just the immediately previous one -- is refused, never only the latest.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/
    """
    lw, function_name, function_arn = _create_role_bucket_and_function(ctx)

    rev1 = lw.put_resource_policy(resourceArn=function_arn, policy=_policy("v1", function_arn))["revisionId"]
    rev2 = lw.put_resource_policy(
        resourceArn=function_arn, policy=_policy("v2", function_arn), revisionId=rev1
    )["revisionId"]
    assert rev2 != rev1, f"revision id did not change after a successful update: {rev2!r}"

    # rev1 is now two generations stale; it must still be refused, not just rev2's predecessor.
    code, message = _error(lambda: lw.put_resource_policy(
        resourceArn=function_arn, policy=_policy("v3-rejected", function_arn), revisionId=rev1
    ))
    assert code == "ConflictException", f"stale two-generations-old revision id gave {code}: {message!r}"
    assert message == (
        "The policy was updated or deleted by another request. Try again with the latest "
        "policy revisionId."
    ), f"unexpected conflict message {message!r}"

    unchanged = lw.get_resource_policy(resourceArn=function_arn)
    assert unchanged["revisionId"] == rev2, (
        f"the rejected stale PUT still moved the revision id to {unchanged['revisionId']!r}, "
        f"expected it to stay at {rev2!r}"
    )
    assert json.loads(unchanged["policy"])["Statement"][0]["Sid"] == "v2", (
        "the rejected stale PUT changed the policy content"
    )

    rev3 = lw.put_resource_policy(
        resourceArn=function_arn, policy=_policy("v3", function_arn), revisionId=rev2
    )["revisionId"]
    assert rev3 not in (rev1, rev2), f"third revision id {rev3!r} collided with an earlier one"

    final = lw.get_resource_policy(resourceArn=function_arn)
    assert final["revisionId"] == rev3, f"expected revision id {rev3!r}, got {final['revisionId']!r}"
    assert json.loads(final["policy"])["Statement"][0]["Sid"] == "v3", (
        f"expected the v3 policy content, got {final['policy']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
