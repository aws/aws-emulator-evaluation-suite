"""create-web-function-revision-accepts-a-customer-managed-kms-key-and-echoes-its-arn."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-web-function-revision-accepts-a-customer-managed-kms-key-and-echoes-its-arn"
GROUP = "encryption"
SERVICES = ["iam", "kms", "lambda-web", "s3"]

_SERVER_SRC = """
const http = require('http');
const [host, port] = (process.env.AWS_LAMBDA_HTTP_ENDPOINT || '0.0.0.0:3000').split(':');
http.createServer((req, res) => {
  res.writeHead(200, {'content-type': 'text/plain'});
  res.end('ok');
}).listen(Number(port), host);
"""


def _zip_bytes(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.js", source)
    return buf.getvalue()


def _code_of(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code")


def _message_of(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Message", "")


def _teardown(undo, *not_found: str):
    """A cleanup that runs ``undo()``, tolerant only of the resource's own not-found codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if _code_of(exc) in not_found:
                return
            raise

    return run_undo


def _remaining_s(ctx, cap_s: float) -> float:
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-lwkms-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    return role_arn


def _create_code_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-xsvc-lwkms-")
    kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket_name), "NoSuchBucket"))
    s3.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowLambdaToFetchDeploymentPackage",
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": ["s3:GetObject", "s3:GetObjectVersion"],
            "Resource": f"arn:aws:s3:::{bucket_name}/*",
            "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}},
        }],
    }))
    return bucket_name


def _put_code_object(ctx, s3, bucket_name: str, key: str) -> None:
    put = s3.put_object(Bucket=bucket_name, Key=key, Body=_zip_bytes(_SERVER_SRC))
    ctx.on_cleanup(_teardown(
        lambda: s3.delete_object(Bucket=bucket_name, Key=key, VersionId=put["VersionId"]),
        "NoSuchKey", "NoSuchVersion",
    ))


def _create_cmk_for_function(ctx, function_name: str) -> str:
    """A symmetric CMK whose policy lets the account manage it and lets Lambda decrypt data keys
    for this function's revisions, scoped by SourceArn as the Web Functions encryption guide
    requires.
    """
    kms = ctx.client("kms")
    revision_scope = f"arn:aws:lambda:{ctx.region}:{ctx.account}:web-function/{function_name}/revision/*"
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableAccountRootAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowLambdaToDecryptThisFunctionsRevisions",
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "kms:Decrypt",
                "Resource": "*",
                "Condition": {"StringLike": {"aws:SourceArn": revision_scope}},
            },
        ],
    })
    key_arn = kms.create_key(Policy=policy, Description=f"sim2real {CHECK}")["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))
    return key_arn


def _wait_for_role_to_be_assumable(ctx, create_fn):
    """Retries CreateWebFunction only through the window where a just-created execution role
    cannot yet be assumed; any other error is the check's own to see.
    """
    deadline = time.monotonic() + _remaining_s(ctx, 90.0)
    while True:
        try:
            return create_fn()
        except ClientError as exc:
            msg = _message_of(exc).lower()
            if _code_of(exc) != "ValidationException" or "role" not in msg or "assum" not in msg:
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5)


def _delete_web_function(lw, function_name: str) -> None:
    lw.delete_web_function(functionName=function_name)
    # The service deletes the function in the background, still using its revisions' key.
    lw.get_waiter("web_function_deleted").wait(
        functionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 25}
    )


def _poll_revision_terminal(ctx, lw, function_name: str, revision_id: str) -> dict:
    deadline = time.monotonic() + _remaining_s(ctx, 240.0)
    while True:
        got = lw.get_web_function_revision(functionName=function_name, revisionId=revision_id)
        if got["state"] in ("Active", "Failed"):
            return got
        if time.monotonic() > deadline:
            raise AssertionError(f"revision {revision_id!r} still {got['state']!r} past its deadline")
        time.sleep(3)


@tags("axis:happy-path", "cap:c1", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new web function revision that names a customer managed KMS key in ``kmsKeyArn`` reaches
    Active and a later GetWebFunctionRevision echoes that exact key ARN, while an earlier revision
    created with no key keeps answering with none.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/web-functions-encryption.html
    """
    lw = ctx.client("lambda-web")
    s3 = ctx.client("s3")
    function_name = ctx.unique_name("sim2real-xsvc-lwkms-fn-")

    role_arn = _create_execution_role(ctx)
    bucket_name = _create_code_bucket(ctx)
    _put_code_object(ctx, s3, bucket_name, "app-v1.zip")
    key_arn = _create_cmk_for_function(ctx, function_name)

    created = _wait_for_role_to_be_assumable(ctx, lambda: lw.create_web_function(
        functionName=function_name,
        revisionConfig={
            "buildConfig": {
                "codeConfig": {"s3Object": {"bucket": bucket_name, "key": "app-v1.zip"}},
                "runtimeConfig": {"runtime": "nodejs24.x"},
            },
            "serviceConfig": {"executionRoleArn": role_arn},
        },
        endpointConfig={"endpointName": "home", "endpointType": "HomeRegion",
                        "authType": "ApplicationManaged"},
    ))
    ctx.on_cleanup(_teardown(
        lambda: _delete_web_function(lw, function_name), "ResourceNotFoundException",
    ))
    revision_id_1 = created["revision"]["revisionId"]

    rev1 = _poll_revision_terminal(ctx, lw, function_name, revision_id_1)
    assert rev1["state"] == "Active", (
        f"the AWS-owned-key revision reached {rev1['state']!r} ({rev1.get('stateReason')!r}), "
        f"expected Active"
    )
    assert "kmsKeyArn" not in rev1, (
        f"a revision created with no kmsKeyArn must not echo one, got {rev1.get('kmsKeyArn')!r}"
    )

    _put_code_object(ctx, s3, bucket_name, "app-v2.zip")
    created_2 = lw.create_web_function_revision(
        functionName=function_name,
        kmsKeyArn=key_arn,
        buildConfig={
            "codeConfig": {"s3Object": {"bucket": bucket_name, "key": "app-v2.zip"}},
            "runtimeConfig": {"runtime": "nodejs24.x"},
        },
        serviceConfig={"executionRoleArn": role_arn},
    )
    revision_id_2 = created_2["revisionId"]
    assert revision_id_2 != revision_id_1, (
        f"CreateWebFunctionRevision reused the first revision id {revision_id_1!r}"
    )
    assert created_2.get("kmsKeyArn") == key_arn, (
        f"CreateWebFunctionRevision's own response held kmsKeyArn={created_2.get('kmsKeyArn')!r}, "
        f"expected the key {key_arn!r} it was given"
    )

    rev2 = _poll_revision_terminal(ctx, lw, function_name, revision_id_2)
    assert rev2["state"] == "Active", (
        f"the customer-managed-key revision reached {rev2['state']!r} "
        f"({rev2.get('stateReason')!r}), expected Active"
    )
    assert rev2["kmsKeyArn"] == key_arn, (
        f"GetWebFunctionRevision answered kmsKeyArn={rev2.get('kmsKeyArn')!r}, expected {key_arn!r}"
    )

    # An independent read of the first revision, issued after the second exists: its encryption
    # configuration must be untouched by a later, differently-encrypted revision.
    still1 = lw.get_web_function_revision(functionName=function_name, revisionId=revision_id_1)
    assert "kmsKeyArn" not in still1, (
        f"the first revision picked up kmsKeyArn={still1.get('kmsKeyArn')!r} from the second "
        f"revision's settings; each revision's encryption key is fixed at creation"
    )
    assert still1["state"] == "Active", f"the first revision's state changed to {still1['state']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
