"""endpoint-latest-revision-mode-rejects-switching-onto-a-non-active-revision."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "endpoint-latest-revision-mode-rejects-switching-onto-a-non-active-revision"
GROUP = "endpoints"
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


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_revision_terminal(ctx, lw, function_name: str, revision_id: str, *, budget_s: float = 180.0,
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


def _poll_endpoint(ctx, lw, function_name: str, endpoint_name: str, settled, *,
                   budget_s: float = 180.0, interval_s: float = 2.0) -> dict:
    """``GetWebFunctionEndpoint`` once ``settled(endpoint)`` holds."""
    budget_s = _budget_s(ctx, budget_s)
    deadline = time.monotonic() + budget_s
    while True:
        got = lw.get_web_function_endpoint(functionName=function_name, endpointName=endpoint_name)
        if settled(got):
            return got
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"endpoint {endpoint_name!r} settling: the run budget ended first; not graded"
                )
            raise AssertionError(
                f"endpoint {endpoint_name!r} still state={got.get('state')!r} "
                f"updateStatus={got.get('updateStatus')!r} after {budget_s}s"
            )
        time.sleep(interval_s)


def _create_role_and_bucket(ctx):
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """Switching an endpoint's auto-deployment mode to LatestRevision is refused while the
    function's newest revision is Failed, and the same switch succeeds once that revision is
    deleted and the newest remaining revision is Active.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/web-functions-deployment.html
    """
    lw = ctx.client("lambda-web")
    s3 = ctx.client("s3")
    role_arn, bucket_name = _create_role_and_bucket(ctx)
    function_name = ctx.unique_name("sim2real-behav-lw-fn-")

    put_a = s3.put_object(Bucket=bucket_name, Key="code-a.zip", Body=_zip_bytes(_SERVER_SRC))
    ctx.on_cleanup(_teardown(
        lambda: s3.delete_object(Bucket=bucket_name, Key="code-a.zip", VersionId=put_a["VersionId"]),
        "NoSuchKey", "NoSuchVersion",
    ))

    created = _create_web_function(
        ctx, lw,
        functionName=function_name,
        revisionConfig={
            "buildConfig": {
                "codeConfig": {"s3Object": {"bucket": bucket_name, "key": "code-a.zip"}},
                "runtimeConfig": {"runtime": "nodejs24.x"},
            },
            "serviceConfig": {"executionRoleArn": role_arn},
        },
        endpointConfig={"endpointName": "ep", "endpointType": "HomeRegion",
                        "authType": "ApplicationManaged", "autoDeploymentMode": "Disabled"},
    )
    ctx.on_cleanup(_teardown(
        lambda: lw.delete_web_function(functionName=function_name), "ResourceNotFoundException",
    ))
    revision_a = created["revision"]["revisionId"]
    rev_a = _poll_revision_terminal(ctx, lw, function_name, revision_a)
    assert rev_a["state"] == "Active", (
        f"revision A reached {rev_a['state']!r} ({rev_a.get('stateReason')!r}), expected Active"
    )
    endpoint = created["endpoint"]
    assert endpoint["autoDeploymentMode"] == "Disabled", (
        f"endpoint autoDeploymentMode was {endpoint['autoDeploymentMode']!r} at creation, "
        f"expected 'Disabled'"
    )

    # Revision B deliberately uploads a readable object that is not a valid zip archive, so
    # the build fails deterministically and the revision reaches Failed rather than Active.
    put_b = s3.put_object(Bucket=bucket_name, Key="code-b.zip", Body=b"not a zip archive")
    ctx.on_cleanup(_teardown(
        lambda: s3.delete_object(Bucket=bucket_name, Key="code-b.zip", VersionId=put_b["VersionId"]),
        "NoSuchKey", "NoSuchVersion",
    ))
    created_b = lw.create_web_function_revision(
        functionName=function_name,
        buildConfig={
            "codeConfig": {"s3Object": {"bucket": bucket_name, "key": "code-b.zip"}},
            "runtimeConfig": {"runtime": "nodejs24.x"},
        },
        serviceConfig={"executionRoleArn": role_arn},
    )
    revision_b = created_b["revisionId"]
    ctx.on_cleanup(_teardown(
        lambda: lw.delete_web_function_revision(functionName=function_name, revisionId=revision_b),
        "ResourceNotFoundException",
    ))
    rev_b = _poll_revision_terminal(ctx, lw, function_name, revision_b)
    assert rev_b["state"] == "Failed", (
        f"revision B (built from a code object that is not a zip archive) reached "
        f"{rev_b['state']!r}, expected Failed"
    )
    assert rev_b["stateReason"] == "Failed to read zip file: zip: not a valid zip file", (
        f"a Failed revision from an invalid zip body gave stateReason {rev_b['stateReason']!r}"
    )

    # The endpoint settles before it is updated, so a refusal below cannot be the one for an
    # endpoint still being modified.
    ready = _poll_endpoint(
        ctx, lw, function_name, "ep",
        lambda e: e["state"] in ("Active", "Failed")
        and e.get("updateStatus") in (None, "Successful", "Failed"),
    )
    assert ready["state"] == "Active", (
        f"the endpoint reached {ready['state']!r} ({ready.get('stateReason')!r}), expected Active"
    )

    # The one broken thing: switching to LatestRevision while B (the newest revision) is Failed.
    code, message = _error(lambda: lw.update_web_function_endpoint(
        functionName=function_name, endpointName="ep", autoDeploymentMode="LatestRevision",
    ))
    assert code == "ConflictException", (
        f"switching to LatestRevision while the newest revision is Failed gave {code}: "
        f"{message!r}, expected ConflictException"
    )
    expected_message = (
        f"The latest revision {revision_b} is in Failed state and cannot be deployed. Only "
        "revisions in Active state can be deployed. Create a new revision."
    )
    assert message == expected_message, f"unexpected conflict message {message!r}"

    unchanged = lw.get_web_function_endpoint(functionName=function_name, endpointName="ep")
    assert unchanged["autoDeploymentMode"] == "Disabled", (
        f"the rejected switch still changed autoDeploymentMode to "
        f"{unchanged['autoDeploymentMode']!r}"
    )

    # Positive control: once B is gone, A -- Active -- is the newest revision, and the same
    # switch succeeds.
    lw.delete_web_function_revision(functionName=function_name, revisionId=revision_b)

    code_after, _ = _error(lambda: lw.get_web_function_revision(
        functionName=function_name, revisionId=revision_b
    ))
    assert code_after == "ResourceNotFoundException", (
        f"GetWebFunctionRevision on the deleted revision B gave {code_after}, "
        f"expected ResourceNotFoundException"
    )

    switched = lw.update_web_function_endpoint(
        functionName=function_name, endpointName="ep", autoDeploymentMode="LatestRevision",
    )
    assert switched["autoDeploymentMode"] == "LatestRevision", (
        f"the switch accepted by the API still reported autoDeploymentMode "
        f"{switched['autoDeploymentMode']!r}"
    )
    settled = _poll_endpoint(
        ctx, lw, function_name, "ep",
        lambda e: e.get("updateStatus") in ("Successful", "Failed"),
    )
    assert settled["updateStatus"] == "Successful", (
        f"the switch to LatestRevision settled as {settled['updateStatus']!r} "
        f"({settled.get('updateStatusReason')!r}), expected Successful"
    )
    assert settled["autoDeploymentMode"] == "LatestRevision", (
        f"the settled endpoint reports autoDeploymentMode {settled['autoDeploymentMode']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
