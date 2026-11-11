"""list-web-function-revisions-pages-through-every-revision-exactly-once."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-web-function-revisions-pages-through-every-revision-exactly-once"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListWebFunctionRevisions, driven one small page at a time, visits every revision the
    check created exactly once, and an unpaged call returns the same revisions.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/web-functions-deployment.html
    """
    lw = ctx.client("lambda-web")
    s3 = ctx.client("s3")
    role_arn, bucket_name = _create_role_and_bucket(ctx)
    function_name = ctx.unique_name("sim2real-behav-lw-fn-")

    put = s3.put_object(Bucket=bucket_name, Key="code.zip", Body=_zip_bytes(_SERVER_SRC))
    ctx.on_cleanup(_teardown(
        lambda: s3.delete_object(Bucket=bucket_name, Key="code.zip", VersionId=put["VersionId"]),
        "NoSuchKey", "NoSuchVersion",
    ))

    def _build_config():
        return {
            "codeConfig": {"s3Object": {"bucket": bucket_name, "key": "code.zip"}},
            "runtimeConfig": {"runtime": "nodejs24.x"},
        }

    created = _create_web_function(
        ctx, lw,
        functionName=function_name,
        revisionConfig={
            "buildConfig": _build_config(),
            "serviceConfig": {"executionRoleArn": role_arn},
        },
        endpointConfig={"endpointName": "ep", "endpointType": "HomeRegion",
                        "authType": "ApplicationManaged"},
    )
    ctx.on_cleanup(_teardown(
        lambda: lw.delete_web_function(functionName=function_name), "ResourceNotFoundException",
    ))
    revision_ids = [created["revision"]["revisionId"]]

    # Two more revisions, each a distinct serviceConfig so they cannot be confused with the
    # first by anything other than their own revisionId.
    for timeout_seconds in (45, 60):
        added = lw.create_web_function_revision(
            functionName=function_name, buildConfig=_build_config(),
            serviceConfig={"executionRoleArn": role_arn, "timeoutSeconds": timeout_seconds},
        )
        revision_ids.append(added["revisionId"])

    assert len(set(revision_ids)) == 3, f"revision ids were not distinct: {revision_ids!r}"

    pages = 0
    seen_ids: list[str] = []
    next_token = None
    while True:
        kwargs = {"functionName": function_name, "maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        page = lw.list_web_function_revisions(**kwargs)
        assert len(page["revisions"]) <= 1, (
            f"maxResults=1 returned {len(page['revisions'])} revisions in one page"
        )
        pages += 1
        seen_ids.extend(r["revisionId"] for r in page["revisions"])
        next_token = page.get("nextToken")
        if not next_token:
            break
        if pages > 10:
            raise AssertionError(f"ListWebFunctionRevisions did not terminate after {pages} pages")

    assert pages >= 3, (
        f"maxResults=1 over 3 revisions produced only {pages} page(s); expected at least 3"
    )
    assert sorted(seen_ids) == sorted(revision_ids), (
        f"paging collected {seen_ids!r}; expected each of the 3 created revisions "
        f"{revision_ids!r} exactly once"
    )

    # A single unpaged call returns the same membership.
    whole = lw.list_web_function_revisions(functionName=function_name)
    assert whole.get("nextToken") is None, (
        f"a default-sized call for 3 revisions still returned a nextToken: {whole.get('nextToken')!r}"
    )
    assert {r["revisionId"] for r in whole["revisions"]} == set(revision_ids), (
        f"unpaged listing returned {[r['revisionId'] for r in whole['revisions']]!r}, "
        f"expected exactly {revision_ids!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
