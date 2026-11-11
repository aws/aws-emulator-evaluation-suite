"""cli-s3-put-object-triggers-lambda-opensearch-index-verify."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-s3-put-object-triggers-lambda-opensearch-index-verify"
GROUP = "cli-workflow"
SERVICES = ["lambda", "opensearch", "s3"]

_HANDLER_SRC = '''
import json
import os
import urllib.parse
import urllib.request

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest


def handler(event, context):
    s3 = boto3.client("s3")
    session = boto3.Session()
    creds = session.get_credentials().get_frozen_credentials()
    host = os.environ["OPENSEARCH_ENDPOINT"]
    region = os.environ["AWS_REGION"]
    results = []
    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
        obj = s3.get_object(Bucket=bucket, Key=key)
        content = obj["Body"].read().decode("utf-8")
        doc = {"bucket": bucket, "key": key, "content": content}
        doc_id = urllib.parse.quote(key, safe="")
        path = "/sim2real-index/_doc/" + doc_id
        url = "https://" + host + path
        data = json.dumps(doc).encode("utf-8")
        req = AWSRequest(method="PUT", url=url, data=data, headers={"Content-Type": "application/json"})
        SigV4Auth(creds, "es", region).add_auth(req)
        http_req = urllib.request.Request(url, data=data, method="PUT", headers=dict(req.headers))
        with urllib.request.urlopen(http_req, timeout=10) as resp:
            results.append(resp.status)
    return {"indexed": results}
'''


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CLI `aws s3 cp` upload fires an S3 ObjectCreated notification to a Lambda function
    that reads the object and PUTs it into an OpenSearch domain index; verified with a direct
    signed search request against the domain."""
    require_tools("aws")

    account_id = _account_id(ctx)
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    domain_arn_prefix = _create_opensearch_domain(ctx, domain_name, account_id)
    domain_endpoint = _wait_for_domain_active(ctx, domain_name)

    bucket = _create_bucket(ctx)

    role_name = ctx.unique_name("sim2real-role-")
    statements = [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
        {
            "Effect": "Allow",
            "Action": ["es:ESHttpPut", "es:ESHttpPost", "es:ESHttpGet"],
            "Resource": f"{domain_arn_prefix}/*",
        },
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        },
    ]
    role_arn = _create_lambda_role(ctx, role_name, statements)

    function_name = ctx.unique_name("sim2real-fn-")
    zip_path = _make_lambda_zip(_HANDLER_SRC)
    created = _create_lambda_function_cli(
        ctx, function_name, role_arn, zip_path, env={"OPENSEARCH_ENDPOINT": domain_endpoint}, timeout=30
    )
    _wait_for_function_active(ctx, function_name)
    function_arn = created["FunctionArn"]

    _grant_s3_invoke_permission(ctx, function_name, bucket, account_id)
    _configure_s3_notification(ctx, bucket, function_arn)

    key = "incoming/report.txt"
    content = "sim2real-check2-payload"
    local_path = os.path.join(tempfile.mkdtemp(), "report.txt")
    with open(local_path, "w") as f:
        f.write(content)
    _run_aws(ctx, "s3", "cp", local_path, f"s3://{bucket}/{key}")

    doc_id = urllib.parse.quote(key, safe="")
    deadline = time.monotonic() + 90.0
    body = None
    last_status = None
    while time.monotonic() < deadline:
        status, resp = _signed_es_request(ctx, domain_endpoint, "GET", f"/sim2real-index/_doc/{doc_id}")
        last_status = status
        if status == 200 and resp.get("found"):
            body = resp["_source"]
            break
        time.sleep(3)
    assert body is not None, f"document never indexed within 90s (last status={last_status})"
    assert body["bucket"] == bucket, f"indexed doc bucket mismatch: expected {bucket!r}, got {body['bucket']!r}"
    assert body["key"] == key, f"indexed doc key mismatch: expected {key!r}, got {body['key']!r}"
    assert body["content"] == content, (
        f"indexed doc content mismatch: expected {content!r}, got {body['content']!r}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command (str → shell=True, or argv list) with the run's AWS creds + region in the
    env (via ctx.subprocess_env). Raises on non-zero exit when check=True. Returns CompletedProcess."""
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
    """Run a multi-line bash script (set -euo pipefail) with the run's AWS creds configured."""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(
            ctx,
            ["bash", script_path],
            timeout_s=timeout_s,
            check=check,
            env_extra=env_extra,
        )
    finally:
        os.unlink(script_path)


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    """Run an AWS CLI command; return parsed JSON (dict/list) or raw stdout string."""
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _caller_principal_arn(ctx) -> str:
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    if ":assumed-role/" in arn:
        parts = arn.split(":")
        account = parts[4]
        role_name = parts[5].split("/")[1]
        return f"arn:aws:iam::{account}:role/{role_name}"
    return arn


def _create_opensearch_domain(ctx, domain_name: str, account_id: str) -> str:
    client = ctx.client("opensearch")
    domain_arn_prefix = f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}"
    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": _caller_principal_arn(ctx)},
                "Action": "es:ESHttp*",
                "Resource": f"{domain_arn_prefix}/*",
            }
        ],
    }
    client.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
        AccessPolicies=json.dumps(access_policy),
    )
    ctx.on_cleanup(lambda: client.delete_domain(DomainName=domain_name))
    return domain_arn_prefix


def _wait_for_domain_active(ctx, domain_name: str, timeout_s=1800.0, interval_s=30.0) -> str:
    # OpenSearch domain provisioning routinely takes 15-25 minutes; poll for the documented
    # "Processing" -> False / "Created" -> True terminal transition rather than a fixed sleep.
    client = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = client.describe_domain(DomainName=domain_name)["DomainStatus"]
        if not status.get("Processing", True) and status.get("Created", False) and status.get("Endpoint"):
            return status["Endpoint"]
        time.sleep(interval_s)
    raise AssertionError(f"OpenSearch domain {domain_name} did not become active within {timeout_s}s")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=name)


def _create_lambda_role(ctx, role_name: str, policy_statements: list) -> str:
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    _run_aws(
        ctx, "iam", "create-role", "--role-name", role_name, "--assume-role-policy-document", trust_policy
    )
    ctx.on_cleanup(
        lambda: _run_shell(ctx, ["aws", "iam", "delete-role", "--role-name", role_name], check=False)
    )
    policy_name = f"{role_name}-inline"
    _run_aws(
        ctx,
        "iam",
        "put-role-policy",
        "--role-name",
        role_name,
        "--policy-name",
        policy_name,
        "--policy-document",
        json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
    )
    ctx.on_cleanup(
        lambda: _run_shell(
            ctx,
            ["aws", "iam", "delete-role-policy", "--role-name", role_name, "--policy-name", policy_name],
            check=False,
        )
    )
    return f"arn:aws:iam::{_account_id(ctx)}:role/{role_name}"


def _make_lambda_zip(handler_source: str) -> str:
    tmp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(tmp_dir, "function.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_source)
    return zip_path


def _create_lambda_function_cli(
    ctx, function_name: str, role_arn: str, zip_path: str, *, handler="lambda_function.handler", env=None, timeout=30
):
    env_arg = []
    if env:
        env_arg = ["--environment", json.dumps({"Variables": env})]
    deadline = time.monotonic() + 90.0
    last_err = ""
    while time.monotonic() < deadline:
        proc = _run_shell(
            ctx,
            [
                "aws",
                "--output",
                "json",
                "lambda",
                "create-function",

                "--function-name",
                function_name,
                "--runtime",
                "python3.12",
                "--role",
                role_arn,
                "--handler",
                handler,
                "--zip-file",
                f"fileb://{zip_path}",
                "--timeout",
                str(timeout),
                *env_arg,
            ],
            check=False,
        )
        if proc.returncode == 0:
            ctx.on_cleanup(
                lambda: _run_shell(
                    ctx, ["aws", "lambda", "delete-function", "--function-name", function_name], check=False
                )
            )
            return json.loads(proc.stdout)
        last_err = proc.stderr
        if "InvalidParameterValueException" in proc.stderr or "cannot be assumed" in proc.stderr:
            time.sleep(5)
            continue
        raise AssertionError(f"create-function failed: {proc.stderr[-500:]}")
    raise AssertionError(f"create-function did not succeed after role propagation wait: {last_err[-500:]}")


def _wait_for_function_active(ctx, function_name: str, timeout_s=90.0, interval_s=3.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=function_name)
        if cfg["State"] == "Active" and cfg.get("LastUpdateStatus", "Successful") == "Successful":
            return cfg
        time.sleep(interval_s)
    raise AssertionError(f"function {function_name} did not become Active within {timeout_s}s")


def _grant_s3_invoke_permission(ctx, function_name: str, bucket: str, account_id: str) -> None:
    _run_aws(
        ctx,
        "lambda",
        "add-permission",
        "--function-name",
        function_name,
        "--statement-id",
        "s3invoke",
        "--action",
        "lambda:InvokeFunction",
        "--principal",
        "s3.amazonaws.com",
        "--source-arn",
        f"arn:aws:s3:::{bucket}",
        "--source-account",
        account_id,
    )


def _configure_s3_notification(ctx, bucket: str, function_arn: str) -> None:
    config = {
        "LambdaFunctionConfigurations": [
            {"LambdaFunctionArn": function_arn, "Events": ["s3:ObjectCreated:*"]}
        ]
    }
    tmp_dir = tempfile.mkdtemp()
    cfg_path = os.path.join(tmp_dir, "notification.json")
    with open(cfg_path, "w") as f:
        json.dump(config, f)
    _run_aws(
        ctx,
        "s3api",
        "put-bucket-notification-configuration",
        "--bucket",
        bucket,
        "--notification-configuration",
        f"file://{cfg_path}",
    )


def _signed_es_request(ctx, host: str, method: str, path: str, body=None):
    frozen = ctx.client("sts")._request_signer._credentials.get_frozen_credentials()
    credentials = Credentials(frozen.access_key, frozen.secret_key, frozen.token)
    url = f"{ctx.endpoint_url(host)}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    aws_request = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(credentials, "es", ctx.region).add_auth(aws_request)
    http_req = urllib.request.Request(url, data=data, method=method, headers=dict(aws_request.headers))
    try:
        with urllib.request.urlopen(http_req, timeout=15) as resp:
            payload = resp.read().decode("utf-8")
            return resp.status, (json.loads(payload) if payload else {})
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8")
        return exc.code, (json.loads(payload) if payload else {})


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
