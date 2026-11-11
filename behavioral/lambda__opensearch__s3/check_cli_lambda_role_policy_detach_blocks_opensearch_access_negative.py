"""cli-lambda-role-policy-detach-blocks-opensearch-access-negative."""
from __future__ import annotations

import json
import os
import random
import string
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-lambda-role-policy-detach-blocks-opensearch-access-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "opensearch", "s3"]

_HANDLER_SRC = '''
import json
import os
import urllib.error
import urllib.request

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest


def handler(event, context):
    session = boto3.Session()
    creds = session.get_credentials().get_frozen_credentials()
    host = os.environ["OPENSEARCH_ENDPOINT"]
    region = os.environ["AWS_REGION"]
    doc_id = event["doc_id"]
    doc = {"doc_id": doc_id}
    path = "/sim2real-index/_doc/" + doc_id
    url = "https://" + host + path
    data = json.dumps(doc).encode("utf-8")
    req = AWSRequest(method="PUT", url=url, data=data, headers={"Content-Type": "application/json"})
    SigV4Auth(creds, "es", region).add_auth(req)
    http_req = urllib.request.Request(url, data=data, method="PUT", headers=dict(req.headers))
    try:
        with urllib.request.urlopen(http_req, timeout=10) as resp:
            return {"status": resp.status}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "error": exc.read().decode("utf-8")}
'''


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """After `aws iam detach-role-policy` removes the OpenSearch-access policy from a Lambda role, the
    function's write is refused 403 and the document is absent (404); the same write succeeds before
    detaching and after re-attaching."""
    require_tools("aws")

    account_id = _account_id(ctx)
    domain_name = _short_domain_name("d4")
    domain_arn_prefix = _create_opensearch_domain(ctx, domain_name, account_id)
    domain_endpoint = _wait_for_domain_active(ctx, domain_name)

    role_name = ctx.unique_name("sim2real-role-")
    base_statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        }
    ]
    role_arn = _create_lambda_role(ctx, role_name, base_statements)

    policy_name = ctx.unique_name("sim2real-pol-")
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["es:ESHttpPut", "es:ESHttpGet"],
                "Resource": f"{domain_arn_prefix}/*",
            }
        ],
    }
    policy_arn = _create_managed_policy(ctx, policy_name, policy_document)
    _attach_role_policy(ctx, role_name, policy_arn)

    function_name = ctx.unique_name("sim2real-fn-")
    zip_path = _make_lambda_zip(_HANDLER_SRC)
    _create_lambda_function_cli(
        ctx, function_name, role_arn, zip_path, env={"OPENSEARCH_ENDPOINT": domain_endpoint}, timeout=30
    )
    _wait_for_function_active(ctx, function_name)

    # Positive control #1: with the policy attached, the write succeeds and is visible.
    meta1, payload1 = _invoke_lambda_cli(ctx, function_name, {"doc_id": "pre-detach"})
    assert meta1.get("StatusCode") == 200 and "FunctionError" not in meta1, f"unexpected invoke error: meta={meta1}"
    assert payload1["status"] in (200, 201), f"expected 200/201 pre-detach write, got {payload1}"
    status_pre, resp_pre = _signed_es_request(ctx, domain_endpoint, "GET", "/sim2real-index/_doc/pre-detach")
    assert status_pre == 200 and resp_pre.get("found") is True, (
        f"expected pre-detach doc to be readable (200, found=True), got status={status_pre} body={resp_pre}"
    )

    # Break exactly one thing.
    _run_aws(ctx, "iam", "detach-role-policy", "--role-name", role_name, "--policy-arn", policy_arn)

    denied_doc_id, denied_payload = _poll_invoke_until(
        ctx, function_name, "post-detach", lambda p: p.get("status") == 403, timeout_s=600.0
    )
    assert denied_payload["status"] == 403, f"expected 403 after detaching the ES policy, got {denied_payload}"

    status_absent, resp_absent = _signed_es_request(
        ctx, domain_endpoint, "GET", f"/sim2real-index/_doc/{denied_doc_id}"
    )
    assert status_absent == 404 and resp_absent.get("found") is False, (
        f"expected denied write to never land (404, found=False), got status={status_absent} body={resp_absent}"
    )

    # Positive control #2: re-attaching the policy restores the exact same operation.
    _run_aws(ctx, "iam", "attach-role-policy", "--role-name", role_name, "--policy-arn", policy_arn)
    restored_doc_id, restored_payload = _poll_invoke_until(
        ctx, function_name, "post-reattach", lambda p: p.get("status") in (200, 201), timeout_s=600.0
    )
    assert restored_payload["status"] in (200, 201), f"expected 200/201 after re-attaching the policy, got {restored_payload}"
    status_restored, resp_restored = _signed_es_request(
        ctx, domain_endpoint, "GET", f"/sim2real-index/_doc/{restored_doc_id}"
    )
    assert status_restored == 200 and resp_restored.get("found") is True, (
        f"expected restored doc to be readable (200, found=True), got status={status_restored} body={resp_restored}"
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


def _mgmt_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-"}


def _short_domain_name(tag: str) -> str:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"sim2r{tag}{suffix}"[:28]


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
        TagList=[{"Key": k, "Value": v} for k, v in _mgmt_tags().items()],
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
        ctx,
        "iam",
        "create-role",
        "--role-name",
        role_name,
        "--assume-role-policy-document",
        trust_policy,
        "--tags",
        json.dumps([{"Key": k, "Value": v} for k, v in _mgmt_tags().items()]),
    )
    ctx.on_cleanup(
        lambda: _run_shell(ctx, ["aws", "iam", "delete-role", "--role-name", role_name], check=False)
    )
    inline_policy_name = f"{role_name}-inline"
    _run_aws(
        ctx,
        "iam",
        "put-role-policy",
        "--role-name",
        role_name,
        "--policy-name",
        inline_policy_name,
        "--policy-document",
        json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
    )
    ctx.on_cleanup(
        lambda: _run_shell(
            ctx,
            ["aws", "iam", "delete-role-policy", "--role-name", role_name, "--policy-name", inline_policy_name],
            check=False,
        )
    )
    return f"arn:aws:iam::{_account_id(ctx)}:role/{role_name}"


def _create_managed_policy(ctx, policy_name: str, policy_document: dict) -> str:
    result = _run_aws(
        ctx,
        "iam",
        "create-policy",
        "--policy-name",
        policy_name,
        "--policy-document",
        json.dumps(policy_document),
        "--tags",
        json.dumps([{"Key": k, "Value": v} for k, v in _mgmt_tags().items()]),
    )
    policy_arn = result["Policy"]["Arn"]
    ctx.on_cleanup(
        lambda: _run_shell(ctx, ["aws", "iam", "delete-policy", "--policy-arn", policy_arn], check=False)
    )
    return policy_arn


def _attach_role_policy(ctx, role_name: str, policy_arn: str) -> None:
    _run_aws(ctx, "iam", "attach-role-policy", "--role-name", role_name, "--policy-arn", policy_arn)
    ctx.on_cleanup(
        lambda: _run_shell(
            ctx,
            ["aws", "iam", "detach-role-policy", "--role-name", role_name, "--policy-arn", policy_arn],
            check=False,
        )
    )


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
                "--tags",
                json.dumps(_mgmt_tags()),
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


def _cli_major_version(ctx) -> int:
    """Detect installed AWS CLI major version (1 or 2) so callers can gate v2-only flags
    like --cli-binary-format (unsupported on v1)."""
    proc = _run_shell(ctx, ["aws", "--version"], check=False)
    text = proc.stdout + proc.stderr
    if "aws-cli/2" in text:
        return 2
    return 1


def _invoke_lambda_cli(ctx, function_name: str, payload: dict):
    out_dir = tempfile.mkdtemp()
    out_path = os.path.join(out_dir, "out.json")
    payload_path = os.path.join(out_dir, "payload.json")
    with open(payload_path, "w") as f:
        json.dump(payload, f)
    cmd = [
        "aws",
        "--output",
        "json",
        "lambda",
        "invoke",
        "--function-name",
        function_name,
    ]
    if _cli_major_version(ctx) >= 2:
        cmd += ["--cli-binary-format", "raw-in-base64-out"]
    cmd += ["--payload", f"file://{payload_path}", out_path]
    proc = _run_shell(ctx, cmd, check=True)
    meta = json.loads(proc.stdout) if proc.stdout.strip() else {}
    with open(out_path) as f:
        response_payload = json.load(f)
    return meta, response_payload


def _poll_invoke_until(ctx, function_name: str, doc_id_prefix: str, predicate, timeout_s=120.0, interval_s=5.0):
    """Repeatedly invoke with a fresh doc_id (IAM policy changes can take a few seconds to
    propagate) until `predicate(payload)` holds; returns (doc_id, payload) of the matching call."""
    deadline = time.monotonic() + timeout_s
    attempt = 0
    last = None
    while time.monotonic() < deadline:
        attempt += 1
        doc_id = f"{doc_id_prefix}-{attempt}"
        meta, payload = _invoke_lambda_cli(ctx, function_name, {"doc_id": doc_id})
        assert meta.get("StatusCode") == 200 and "FunctionError" not in meta, f"unexpected invoke error: {payload}"
        last = (doc_id, payload)
        if predicate(payload):
            return doc_id, payload
        time.sleep(interval_s)
    raise AssertionError(f"condition never observed within {timeout_s}s; last={last}")


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
