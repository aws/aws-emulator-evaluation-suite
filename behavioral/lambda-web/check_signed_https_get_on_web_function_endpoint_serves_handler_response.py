"""signed-https-get-on-web-function-endpoint-serves-handler-response."""
from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signed-https-get-on-web-function-endpoint-serves-handler-response"
GROUP = "endpoint-invocation"
SERVICES = ["lambda-web"]

_CODE_ZIP_B64 = (
    "UEsDBBQAAAAIAHyiW10K8JOSqgAAAOMAAAAIABwAaW5kZXguanNVVAkAA2wH4WpsB+FqdXgLAAEE6AMAAAToAwAA"
    "NY7BDoIwDIbvPEVvGwnigkeCFy7eNMoL4GjiIm64FaIR390O4qFJ+//9+lc7GwhuRANU4PE5Go9SxFmkZaIXN6Cf"
    "0LMf5Vx7bAkviyYlIxlzIYVqD58EYp8HamkMteuQoUKp8q8jHbDtmBO1s4SWNs17QJGBIHzRduhbY2Puuo62kyKY"
    "R8GJ/Wbw7org7tH/cq1f5b0JfEiyqzFEZspPx3MD8ww7pRQv/gBQSwECHgMUAAAACAB8oltdCvCTkqoAAADjAAAA"
    "CAAYAAAAAAABAAAAtIEAAAAAaW5kZXguanNVVAUAA2wH4Wp1eAsAAQToAwAABOgDAABQSwUGAAAAAAEAAQBOAAAA"
    "7AAAAAAA"
)
_HANDLER_BODY = "sim2real-probe ok"


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


def _poll_until(observe, predicate, *, budget_s: float = 180.0, interval_s: float = 5.0):
    """The first value ``observe()`` returns that satisfies ``predicate``, within a budget."""
    deadline = time.monotonic() + budget_s
    while True:
        value = observe()
        if predicate(value):
            return value
        if time.monotonic() > deadline:
            return value
        time.sleep(interval_s)


def _create_role_bucket_and_endpoint(ctx):
    """Create an execution role, a versioned code bucket and one Active IamAuth endpoint."""
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

    bucket_args = {"Bucket": bucket_name}
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        bucket_args["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**bucket_args)
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
            lw.create_web_function(**create_kwargs)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ValidationException" or time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(_teardown(
        lambda: lw.delete_web_function(functionName=function_name), "ResourceNotFoundException",
    ))

    endpoint = _poll_until(
        lambda: lw.get_web_function_endpoint(functionName=function_name, endpointName="ep"),
        lambda e: e["state"] == "Active",
    )
    assert endpoint["state"] == "Active", (
        f"endpoint did not reach Active within budget: {endpoint['state']!r} "
        f"({endpoint.get('stateReason')!r})"
    )
    return lw, function_name, endpoint["domainName"]


def _http(method, url, headers=None):
    """(status, lowercased headers, text); an HTTPError is captured, not raised."""
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed https scheme
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read().decode()


def _caller_credentials(ctx):
    """The harness's per-run credentials, via the one sanctioned seam (never the ambient chain)."""
    env = ctx.subprocess_env()
    akid, secret = env.get("AWS_ACCESS_KEY_ID"), env.get("AWS_SECRET_ACCESS_KEY")
    assert akid and secret, "ctx.subprocess_env() carried no credentials to sign with"
    return akid, secret, env.get("AWS_SESSION_TOKEN")


def _signed_get(ctx, url, akid, secret, token=None):
    """GET url SigV4-signed for service ``lambda`` in ctx.region, carrying the body-hash header
    that a Lambda Web Function endpoint requires on every signed request."""
    body_hash = hashlib.sha256(b"").hexdigest()
    req = AWSRequest(method="GET", url=url, headers={"X-Amz-Content-SHA256": body_hash})
    SigV4Auth(Credentials(akid, secret, token), "lambda", ctx.region).add_auth(req)
    return _http("GET", url, headers=dict(req.headers.items()))


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A SigV4-signed HTTPS GET to an Active IamAuth web function endpoint's domain is served by
    the deployed revision's handler: status 200 and the exact body the handler code returns."""
    _, _, domain_name = _create_role_bucket_and_endpoint(ctx)
    url = ctx.endpoint_url(domain_name)
    akid, secret, token = _caller_credentials(ctx)

    status, _, text = _poll_until(
        lambda: _signed_get(ctx, url, akid, secret, token),
        lambda r: r[0] == 200,
    )
    assert status == 200, (
        f"signed GET to the Active endpoint domain: expected 200, got {status} ({text!r})"
    )
    assert text == _HANDLER_BODY, (
        f"signed GET to the Active endpoint domain returned body {text!r}, expected the handler's "
        f"literal output {_HANDLER_BODY!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
