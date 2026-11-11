"""outbound-https-fetches-s3-object-via-virtual-hosted-presigned-url."""

from __future__ import annotations

import io
import json
import textwrap
import time
import urllib.parse
import uuid
import zipfile

from botocore.config import Config

from behavioral_harness import tags


CHECK = "outbound-https-fetches-s3-object-via-virtual-hosted-presigned-url"
GROUP = 'networking'
SERVICES = ['lambda']

HANDLER = """\
import json
import urllib.request


def handler(event, context):
    url = event["url"]
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            status = resp.status
            body = resp.read().decode("utf-8")
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return {"ok": True, "status": status, "body": body}
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _create_role(ctx):
    """An execution role this check creates (Lambda trust + basic logging), removed at cleanup."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-exec-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST,
                          Tags=[{"Key": "sim2real:managed", "Value": "true"}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retrying only the fresh-role refusal ("cannot be assumed") for at most 90 s."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90.0
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3.0)  # a role created seconds ago is not yet assumable by Lambda
                continue
            raise


def _cleanup_fn(ctx, lam, name):
    """Delete the function and its log group; an already-absent one is done, anything else raises."""
    from botocore.exceptions import ClientError

    for delete in (lambda: lam.delete_function(FunctionName=name),
                   lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")):
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise


def _wait_active(lam, fn, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return last
        time.sleep(1.0)
    raise AssertionError(f"{fn} did not reach State=Active within {timeout_s}s. Last: {last!r}")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A non-VPC function resolves an S3 virtual-hosted hostname from its sandbox and completes an
    HTTPS GET of a presigned URL, returning status 200 and the object's exact body.
    """
    lam = ctx.client("lambda")
    s3 = ctx.client("s3", config=Config(s3={"addressing_style": "virtual"}))

    bucket = ctx.unique_name("sim2real-behav-lambdadns-")
    key = "payload.txt"
    expected_body = f"sim2real dns-resolution {uuid.uuid4().hex}\n"

    create_kwargs = {"Bucket": bucket}
    # us-east-1 is the one region S3 refuses an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    s3.put_object(Bucket=bucket, Key=key, Body=expected_body.encode("utf-8"))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    url = s3.generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=300
    )
    host = urllib.parse.urlparse(url).hostname
    assert host is not None and host.startswith(bucket), (
        f"test setup did not produce a virtual-hosted-style URL: host={host!r} for bucket "
        f"{bucket!r} (url={url!r})"
    )

    name = ctx.unique_name("sim2real-behav-lambdadns-")
    _create_function(lam,
        FunctionName=name, Runtime="python3.12", Handler="index.handler",
        Role=_create_role(ctx), Code={"ZipFile": _make_zip(HANDLER)},
        MemorySize=128, Timeout=30, Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)

    resp = lam.invoke(FunctionName=name, Payload=json.dumps({"url": url}).encode("utf-8"))
    raw = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"Invoke StatusCode {resp['StatusCode']!r}, payload {raw!r}"
    assert "FunctionError" not in resp, f"handler failed with {resp.get('FunctionError')!r}: {raw!r}"
    body = json.loads(raw)

    assert body.get("ok") is True, (
        f"the handler's own outbound HTTPS GET to the virtual-hosted S3 URL did not succeed "
        f"inside the Lambda execution sandbox: {body!r}"
    )
    assert body.get("status") == 200, f"expected HTTP 200 from S3, got {body.get('status')!r}"
    assert body.get("body") == expected_body, (
        f"S3 object body fetched via the virtual-hosted URL from inside Lambda was "
        f"{body.get('body')!r}, expected {expected_body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
