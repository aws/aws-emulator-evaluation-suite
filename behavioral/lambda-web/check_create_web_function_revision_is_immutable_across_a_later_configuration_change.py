"""create-web-function-revision-is-immutable-across-a-later-configuration-change."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-web-function-revision-is-immutable-across-a-later-configuration-change"
GROUP = "revisions"
SERVICES = ["lambda-web"]

_SERVER_SRC = """
const http = require('http');
const [host, port] = (process.env.AWS_LAMBDA_HTTP_ENDPOINT || 'localhost:3000').split(':');
http.createServer((req, res) => {
  res.writeHead(200, {'content-type': 'text/plain'});
  res.end('sim2real-behav-lw ok');
}).listen(Number(port), host);
"""


def _zip_bytes(source: str, filename: str = "index.js") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(filename, source)
    return buf.getvalue()


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _role_not_yet_assumable(exc) -> bool:
    """True for the ValidationException CreateWebFunction answers while a just-created execution
    role cannot yet be assumed; any other error is the check's to see."""
    err = exc.response.get("Error", {})
    message = (err.get("Message") or "").lower()
    return err.get("Code") == "ValidationException" and "role" in message and "assum" in message


def _create_web_function(ctx, lw, **kwargs):
    """CreateWebFunction, retried only while the execution role is still propagating."""
    timeout_s = _budget_s(ctx, 60.0)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lw.create_web_function(tags={"sim2real": CHECK}, **kwargs)
        except ClientError as exc:
            if not _role_not_yet_assumable(exc):
                raise
            if time.monotonic() > deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(
                        "the execution role becoming assumable: the run budget ended first; "
                        "not graded"
                    ) from exc
                raise
            time.sleep(5)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll_terminal(ctx, lw, function_name: str, revision_id: str, *, budget_s: float = 180.0,
                    interval_s: float = 2.0) -> dict:
    """``GetWebFunctionRevision`` once its state reaches ``Active`` or ``Failed``."""
    budget_s = _budget_s(ctx, budget_s)
    deadline = time.monotonic() + budget_s
    while True:
        got = lw.get_web_function_revision(functionName=function_name, revisionId=revision_id)
        if got["state"] in ("Active", "Failed"):
            return got
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"revision {revision_id!r} reaching a terminal state: the run budget ended "
                    "first; not graded"
                )
            raise AssertionError(
                f"revision {revision_id!r} still {got['state']!r} after {budget_s}s"
            )
        time.sleep(interval_s)


def _create_role_and_bucket(ctx):
    """An execution role and a versioned code bucket, usable by any revision in the check."""
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    role_name = ctx.unique_name("sim2real-behav-lw-role-")
    bucket_name = ctx.unique_name("sim2real-behav-lambdaweb-")

    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    # us-east-1 refuses a LocationConstraint; every other Region requires one.

    _bucket_kwargs = {"Bucket": bucket_name}

    if ctx.region != "us-east-1":

        _bucket_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}

    s3.create_bucket(**_bucket_kwargs)
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket_name), "NoSuchBucket"))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]},
    )
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
    return role_arn, bucket_name


def _put_code(ctx, s3, bucket_name: str, key: str) -> None:
    put = s3.put_object(Bucket=bucket_name, Key=key, Body=_zip_bytes(_SERVER_SRC))
    ctx.on_cleanup(_teardown(
        lambda: s3.delete_object(Bucket=bucket_name, Key=key, VersionId=put["VersionId"]),
        "NoSuchKey", "NoSuchVersion",
    ))


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A web function revision never changes once created: a later CreateWebFunctionRevision
    with different settings produces a new, distinct revision and leaves the first one's
    GetWebFunctionRevision answer exactly as it was.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/web-functions-deployment.html
    """
    lw = ctx.client("lambda-web")
    s3 = ctx.client("s3")
    role_arn, bucket_name = _create_role_and_bucket(ctx)
    function_name = ctx.unique_name("sim2real-behav-lw-fn-")
    _put_code(ctx, s3, bucket_name, "code-v1.zip")

    created = _create_web_function(
        ctx, lw,
        functionName=function_name,
        revisionConfig={
            "buildConfig": {
                "codeConfig": {"s3Object": {"bucket": bucket_name, "key": "code-v1.zip"}},
                "runtimeConfig": {"runtime": "nodejs24.x"},
            },
            "serviceConfig": {"executionRoleArn": role_arn, "timeoutSeconds": 20},
        },
        endpointConfig={"endpointName": "ep", "endpointType": "HomeRegion",
                        "authType": "ApplicationManaged"},
    )
    ctx.on_cleanup(_teardown(
        lambda: lw.delete_web_function(functionName=function_name), "ResourceNotFoundException",
    ))
    revision_id_1 = created["revision"]["revisionId"]

    rev1 = _poll_terminal(ctx, lw, function_name, revision_id_1)
    assert rev1["state"] == "Active", (
        f"the initial revision reached {rev1['state']!r} ({rev1.get('stateReason')!r}), "
        f"expected Active"
    )
    assert rev1["serviceConfig"]["timeoutSeconds"] == 20, (
        f"initial revision timeoutSeconds was {rev1['serviceConfig']['timeoutSeconds']!r}, expected 20"
    )
    created_at_1 = rev1["createdAt"]

    _put_code(ctx, s3, bucket_name, "code-v2.zip")
    created_2 = lw.create_web_function_revision(
        functionName=function_name,
        buildConfig={
            "codeConfig": {"s3Object": {"bucket": bucket_name, "key": "code-v2.zip"}},
            "runtimeConfig": {"runtime": "nodejs24.x"},
        },
        serviceConfig={"executionRoleArn": role_arn, "timeoutSeconds": 40,
                        "environmentVariables": {"GEN": "v2"}},
    )
    revision_id_2 = created_2["revisionId"]
    assert revision_id_2 != revision_id_1, (
        f"a second CreateWebFunctionRevision reused the first revision id {revision_id_1!r} "
        f"instead of minting a new one"
    )
    ctx.on_cleanup(_teardown(
        lambda: lw.delete_web_function_revision(functionName=function_name, revisionId=revision_id_2),
        "ResourceNotFoundException",
    ))

    rev2 = _poll_terminal(ctx, lw, function_name, revision_id_2)
    assert rev2["state"] == "Active", (
        f"the second revision reached {rev2['state']!r} ({rev2.get('stateReason')!r}), "
        f"expected Active"
    )
    assert rev2["serviceConfig"]["timeoutSeconds"] == 40, (
        f"second revision timeoutSeconds was {rev2['serviceConfig']['timeoutSeconds']!r}, expected 40"
    )
    assert rev2["serviceConfig"].get("environmentVariables") == {"GEN": "v2"}, (
        f"second revision environmentVariables was "
        f"{rev2['serviceConfig'].get('environmentVariables')!r}, expected {{'GEN': 'v2'}}"
    )

    # The first revision is read again, after the second exists: its answer is unchanged.
    still1 = lw.get_web_function_revision(functionName=function_name, revisionId=revision_id_1)
    assert still1["state"] == "Active", (
        f"the first revision's state changed to {still1['state']!r} after a later revision "
        f"was created"
    )
    assert still1["serviceConfig"]["timeoutSeconds"] == 20, (
        f"the first revision's timeoutSeconds became {still1['serviceConfig']['timeoutSeconds']!r} "
        f"after a later revision was created; a revision must stay immutable"
    )
    assert still1["serviceConfig"].get("environmentVariables") in (None, {}), (
        f"the first revision picked up environmentVariables "
        f"{still1['serviceConfig'].get('environmentVariables')!r} from the second revision's "
        f"settings; a revision must stay immutable"
    )
    assert still1["buildConfig"]["codeConfig"]["s3Object"]["key"] == "code-v1.zip", (
        f"the first revision's code pointer changed to "
        f"{still1['buildConfig']['codeConfig']['s3Object']['key']!r}"
    )
    assert still1["revisionArn"] == rev1["revisionArn"], "the first revision's ARN changed"
    assert still1["createdAt"] == created_at_1, "the first revision's createdAt changed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
