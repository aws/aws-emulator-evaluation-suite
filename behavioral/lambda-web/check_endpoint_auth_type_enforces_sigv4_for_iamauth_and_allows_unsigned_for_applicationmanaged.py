"""endpoint-auth-type-enforces-sigv4-for-iamauth-and-allows-unsigned-for-applicationmanaged."""
from __future__ import annotations

import hashlib
import io
import json
import ssl
import time
import urllib.error
import urllib.request
import zipfile

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "endpoint-auth-type-enforces-sigv4-for-iamauth-and-allows-unsigned-for-applicationmanaged"
GROUP = "endpoints"
SERVICES = ["lambda-web"]

# The application serves one fixed body to every request; it never reflects the request.
_SERVED_BODY = "sim2real-behav-lw ok"
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


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    ssl_ctx = ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)
    if verify is False:
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    return ssl_ctx


def _caller_credentials(ctx) -> Credentials:
    """The harness's per-run credentials, via the one sanctioned seam (never the ambient chain)."""
    env = ctx.subprocess_env()
    akid, secret = env.get("AWS_ACCESS_KEY_ID"), env.get("AWS_SECRET_ACCESS_KEY")
    assert akid and secret, "ctx.subprocess_env() carried no credentials to sign with"
    return Credentials(akid, secret, env.get("AWS_SESSION_TOKEN"))


def _http(ctx, url: str, headers=None):
    """GET ``url``; returns (status, lowercased response headers, body text)."""
    target, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        target, method="GET", headers={**route_headers, **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, context=_ssl_context(ctx.http_verify), timeout=30) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read().decode()
    except urllib.error.URLError:
        # The domain name was only just minted; name resolution can lag briefly.
        return 0, {}, ""


def _poll_until(ctx, observe, predicate, *, description: str, budget_s: float = 180.0,
                interval_s: float = 2.0):
    """The first value ``observe()`` returns that satisfies ``predicate``, within a budget."""
    budget_s = _budget_s(ctx, budget_s)
    deadline = time.monotonic() + budget_s
    while True:
        value = observe()
        if predicate(value):
            return value
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(
                f"{description} not met within {budget_s}s; last value was {value!r}"
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


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An IamAuth endpoint refuses an unsigned HTTP request and serves one signed with SigV4,
    while an ApplicationManaged endpoint on the same revision serves an unsigned request.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/web-functions-endpoint-access-control.html
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

    created = _create_web_function(
        ctx, lw,
        functionName=function_name,
        revisionConfig={
            "buildConfig": {
                "codeConfig": {"s3Object": {"bucket": bucket_name, "key": "code.zip"}},
                "runtimeConfig": {"runtime": "nodejs24.x"},
            },
            "serviceConfig": {"executionRoleArn": role_arn},
        },
        endpointConfig={"endpointName": "am", "endpointType": "HomeRegion",
                        "authType": "ApplicationManaged"},
    )
    ctx.on_cleanup(_teardown(
        lambda: lw.delete_web_function(functionName=function_name), "ResourceNotFoundException",
    ))
    revision_id = created["revision"]["revisionId"]

    rev = _poll_until(
        ctx,
        lambda: lw.get_web_function_revision(functionName=function_name, revisionId=revision_id),
        lambda r: r["state"] in ("Active", "Failed"),
        description="the revision reaching a terminal state",
    )
    assert rev["state"] == "Active", (
        f"the revision reached {rev['state']!r} ({rev.get('stateReason')!r}), expected Active"
    )

    am_endpoint = _poll_until(
        ctx,
        lambda: lw.get_web_function_endpoint(functionName=function_name, endpointName="am"),
        lambda e: e["state"] in ("Active", "Failed"),
        description="the ApplicationManaged endpoint reaching a terminal state",
    )
    assert am_endpoint["state"] == "Active", (
        f"the ApplicationManaged endpoint reached {am_endpoint['state']!r} "
        f"({am_endpoint.get('stateReason')!r}), expected Active"
    )
    am_domain = am_endpoint["domainName"]

    lw.create_web_function_endpoint(
        functionName=function_name, endpointName="iam", endpointType="HomeRegion",
        authType="IamAuth", revisionWeights=[{"revisionId": revision_id, "weight": 100}],
    )
    ctx.on_cleanup(_teardown(
        lambda: lw.delete_web_function_endpoint(functionName=function_name, endpointName="iam"),
        "ResourceNotFoundException",
    ))
    iam_endpoint = _poll_until(
        ctx,
        lambda: lw.get_web_function_endpoint(functionName=function_name, endpointName="iam"),
        lambda e: e["state"] in ("Active", "Failed"),
        description="the IamAuth endpoint reaching a terminal state",
    )
    assert iam_endpoint["state"] == "Active", (
        f"the IamAuth endpoint reached {iam_endpoint['state']!r} "
        f"({iam_endpoint.get('stateReason')!r}), expected Active"
    )
    iam_domain = iam_endpoint["domainName"]

    # IamAuth checks the caller's identity against a resource-based policy; grant this
    # check's own caller permission to invoke the endpoint it just created.
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    lw.put_resource_policy(resourceArn=created["functionArn"], policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "sim2realBehavInvoke", "Effect": "Allow",
            "Principal": {"AWS": caller_arn}, "Action": "lambda:InvokeWebFunctionEndpoint",
            "Resource": iam_endpoint["endpointArn"],
        }],
    }))
    ctx.on_cleanup(_teardown(
        lambda: lw.delete_resource_policy(resourceArn=created["functionArn"]),
        "ResourceNotFoundException",
    ))

    # ApplicationManaged: an unsigned request is forwarded straight to the application. The
    # domain was only just minted, so the first touches poll past a brief resolution lag.
    _, _, am_body = _poll_until(
        ctx,
        lambda: _http(ctx, f"{am_domain}/"),
        lambda r: r[0] == 200,
        description="an unsigned GET to the ApplicationManaged endpoint being served",
    )
    assert am_body == _SERVED_BODY, (
        f"ApplicationManaged endpoint body was {am_body!r}, expected the application's fixed "
        f"{_SERVED_BODY!r}"
    )

    signer_creds = _caller_credentials(ctx)

    def _signed_get(path: str):
        url = f"{iam_domain}{path}"
        target, route_headers = ctx.endpoint_route(url)
        headers = {**route_headers, "X-Amz-Content-SHA256": hashlib.sha256(b"").hexdigest()}
        aws_req = AWSRequest(method="GET", url=target, headers=headers)
        SigV4Auth(signer_creds, "lambda", ctx.region).add_auth(aws_req)
        return _http(ctx, url, headers=dict(aws_req.headers))

    # Warm the IamAuth domain's resolution with a signed request before using it as a
    # readiness signal for the unsigned check below.
    _, _, signed_body = _poll_until(
        ctx,
        lambda: _signed_get("/"), lambda r: r[0] == 200,
        description="a signed GET to the IamAuth endpoint being served",
    )
    assert signed_body == _SERVED_BODY, (
        f"IamAuth endpoint body for the signed request was {signed_body!r}, expected "
        f"{_SERVED_BODY!r}"
    )

    # IamAuth: the same unsigned request is refused before it reaches the application.
    status, headers, body = _http(ctx, f"{iam_domain}/")
    assert status == 403, f"unsigned GET to the IamAuth endpoint got {status}: {body!r}, expected 403"
    request_id = headers.get("lambda-web-request-id")
    assert request_id, f"the refusal carried no lambda-web-request-id header: {headers!r}"
    expected_body = (
        "<!DOCTYPE html>\n<html>\n<head>\n    <title>HTTP Error 403</title>\n</head>\n<body>\n"
        "    <h1>403 Forbidden</h1>\n    <p>You are not authorized to access this endpoint.</p>\n"
        f"    <p>Request ID: {request_id}</p>\n</body>\n</html>"
    )
    assert body == expected_body, f"unexpected refusal body {body!r}"

    # The endpoint is still healthy for a signed caller after the refusal.
    signed_status2, _, signed_body2 = _signed_get("/")
    assert signed_status2 == 200 and signed_body2 == _SERVED_BODY, (
        f"signed call after the refusal got {signed_status2}: {signed_body2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
