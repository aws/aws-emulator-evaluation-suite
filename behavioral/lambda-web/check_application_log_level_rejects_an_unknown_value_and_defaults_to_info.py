"""application-log-level-rejects-an-unknown-value-and-defaults-to-info."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "application-log-level-rejects-an-unknown-value-and-defaults-to-info"
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


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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


def _create_role_bucket_and_code(ctx):
    """An execution role and one uploaded code object, usable by any revision in the check."""
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
    put = s3.put_object(Bucket=bucket_name, Key="code.zip", Body=_zip_bytes(_SERVER_SRC))
    ctx.on_cleanup(_teardown(
        lambda: s3.delete_object(Bucket=bucket_name, Key="code.zip", VersionId=put["VersionId"]),
        "NoSuchKey", "NoSuchVersion",
    ))
    return role_arn, bucket_name


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A revision's applicationLogLevel rejects a value outside its enum with a validation
    error naming the value, and a revision that omits it defaults to INFO.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/web-functions-telemetry.html
    """
    lw = ctx.client("lambda-web")
    role_arn, bucket_name = _create_role_bucket_and_code(ctx)
    function_name = ctx.unique_name("sim2real-behav-lw-fn-")

    def _build_config():
        return {
            "codeConfig": {"s3Object": {"bucket": bucket_name, "key": "code.zip"}},
            "runtimeConfig": {"runtime": "nodejs24.x"},
        }

    bad_level = "VERBOSE"
    code, message = _error(lambda: lw.create_web_function(
        functionName=function_name,
        revisionConfig={
            "buildConfig": _build_config(),
            "serviceConfig": {
                "executionRoleArn": role_arn,
                "telemetryConfig": {"loggingConfig": {"applicationLogLevel": bad_level}},
            },
        },
        endpointConfig={"endpointName": "ep", "endpointType": "HomeRegion",
                        "authType": "ApplicationManaged"},
        tags={"sim2real": CHECK},
    ))
    assert code == "ValidationException", (
        f"applicationLogLevel={bad_level!r} gave {code}: {message!r}, expected ValidationException"
    )
    expected_message = (
        f"1 validation error detected: Value '{bad_level}' at "
        "'revisionConfig.serviceConfig.telemetryConfig.loggingConfig.applicationLogLevel' "
        "failed to satisfy constraint: Member must satisfy enum value set: "
        "[FATAL, TRACE, WARN, ERROR, INFO, DEBUG]"
    )
    assert message == expected_message, f"unexpected validation message {message!r}"

    # The rejected call created nothing: the function name stays free.
    nf_code, _ = _error(lambda: lw.get_web_function(functionName=function_name))
    assert nf_code == "ResourceNotFoundException", (
        f"a function exists at {function_name!r} after its only create was rejected: {nf_code}"
    )

    # Positive control: the same shape, a valid level, succeeds and the default takes effect
    # when the sibling field is left out.
    created = _create_web_function(
        ctx, lw,
        functionName=function_name,
        revisionConfig={
            "buildConfig": _build_config(),
            "serviceConfig": {
                "executionRoleArn": role_arn,
                "telemetryConfig": {"loggingConfig": {"systemLogLevel": "WARN"}},
            },
        },
        endpointConfig={"endpointName": "ep", "endpointType": "HomeRegion",
                        "authType": "ApplicationManaged"},
    )
    ctx.on_cleanup(_teardown(
        lambda: lw.delete_web_function(functionName=function_name), "ResourceNotFoundException",
    ))
    revision_id = created["revision"]["revisionId"]
    rev = _poll_terminal(ctx, lw, function_name, revision_id)
    assert rev["state"] == "Active", (
        f"the valid revision reached {rev['state']!r} ({rev.get('stateReason')!r}), expected Active"
    )
    logging_config = rev["serviceConfig"]["telemetryConfig"]["loggingConfig"]
    assert logging_config.get("applicationLogLevel") == "INFO", (
        f"applicationLogLevel defaulted to {logging_config.get('applicationLogLevel')!r}, "
        f"expected 'INFO' when the field is omitted"
    )
    assert logging_config.get("systemLogLevel") == "WARN", (
        f"systemLogLevel was {logging_config.get('systemLogLevel')!r}, expected the 'WARN' this "
        f"revision set"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
