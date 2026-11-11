"""s3-notification-lambda-opensearch-write-failure-negative."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Any

import botocore.exceptions
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-notification-lambda-opensearch-write-failure-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "opensearch", "s3"]


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With S3->Lambda wired but the role absent from the OpenSearch domain policy, the function
    gets a 403, writes an error marker and indexes NO document; granting the role makes the same
    write succeed.
    """
    bucket = _create_bucket(ctx)
    caller_arn = _caller_principal_arn(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _role_name, role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }
        ],
    )
    # Domain access policy allows only the test caller (for verification) — NOT the Lambda role.
    domain = _create_domain(ctx, [caller_arn])
    index = "objects"
    fn = _create_function(
        ctx,
        role_arn,
        _INDEX_HANDLER_WITH_ERROR_MARKER_SRC,
        {"OS_ENDPOINT": domain["endpoint"], "OS_INDEX": index, "MARKER_BUCKET": bucket},
    )
    _add_s3_invoke_permission(ctx, fn["name"], bucket, account_id)
    _put_notification(ctx, bucket, fn["arn"], ["s3:ObjectCreated:*"])

    s3 = ctx.client("s3")
    denied_key = "denied-doc.txt"
    s3.put_object(Bucket=bucket, Key=denied_key, Body=b"blocked-content")

    marker_key = f"errors/{denied_key}.err"
    _wait_for_effect(
        lambda: _object_exists(ctx, bucket, marker_key),
        lambda exists: exists,
        timeout_s=90,
        interval_s=3,
        description=f"error marker {marker_key} written after OpenSearch AccessDenied",
    )
    marker_body = s3.get_object(Bucket=bucket, Key=marker_key)["Body"].read()
    assert marker_body == b"403"

    denied_doc_id = urllib.parse.quote(denied_key, safe="")
    denied_status, _denied_doc = _os_signed_request(
        ctx, domain["endpoint"], "GET", f"/{index}/_doc/{denied_doc_id}"
    )
    assert denied_status == 404

    # Positive control: once the domain grants the role, the identical write succeeds.
    _update_domain_access_policy(ctx, domain["name"], domain["resource_pattern"], [caller_arn, role_arn])

    allowed_key = "allowed-doc.txt"
    s3.put_object(Bucket=bucket, Key=allowed_key, Body=b"now-permitted")
    allowed_doc_id = urllib.parse.quote(allowed_key, safe="")
    status, doc = _wait_for_effect(
        lambda: _os_signed_request(ctx, domain["endpoint"], "GET", f"/{index}/_doc/{allowed_doc_id}"),
        lambda r: r[0] == 200,
        timeout_s=120,
        interval_s=3,
        description="doc indexed once role is granted domain access",
    )
    assert status == 200
    assert doc["_source"]["key"] == allowed_key


_INDEX_HANDLER_WITH_ERROR_MARKER_SRC = '''
import json
import os
import urllib.parse
import urllib.request
import urllib.error
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

REGION = os.environ["AWS_REGION"]
OS_ENDPOINT = os.environ["OS_ENDPOINT"]
INDEX = os.environ["OS_INDEX"]
MARKER_BUCKET = os.environ["MARKER_BUCKET"]

s3 = boto3.client("s3")


def _signed(method, path, body=None):
    creds = boto3.Session().get_credentials().get_frozen_credentials()
    url = "https://" + OS_ENDPOINT + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(creds, "es", REGION).add_auth(req)
    http_req = urllib.request.Request(url, data=req.body, headers=dict(req.headers), method=method)
    try:
        with urllib.request.urlopen(http_req, timeout=20) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def handler(event, context):
    outcomes = []
    for record in event.get("Records", []):
        event_name = record["eventName"]
        bucket = record["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
        doc_id = urllib.parse.quote(key, safe="")
        if event_name.startswith("ObjectCreated"):
            head = s3.head_object(Bucket=bucket, Key=key)
            doc = {
                "key": key,
                "bucket": bucket,
                "size": head["ContentLength"],
                "etag": head["ETag"].strip('"'),
            }
            status, body = _signed("PUT", "/" + INDEX + "/_doc/" + doc_id, doc)
            outcomes.append({"action": "index", "key": key, "status": status})
            if status >= 300:
                print("ERROR indexing " + key + ": " + str(status) + " " + str(body))
                s3.put_object(
                    Bucket=MARKER_BUCKET,
                    Key="errors/" + key + ".err",
                    Body=str(status).encode(),
                )
        elif event_name.startswith("ObjectRemoved"):
            status, body = _signed("DELETE", "/" + INDEX + "/_doc/" + doc_id, None)
            outcomes.append({"action": "delete", "key": key, "status": status})
            if status >= 300 and status != 404:
                print("ERROR deleting " + key + ": " + str(status) + " " + str(body))
    return {"outcomes": outcomes}
'''


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the last result, raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect (default 120s — Kinesis/DDB-stream ESMs can need
    60-120s for cold-start + first delivery; fast effects return as soon as the predicate holds)."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _object_exists(ctx, bucket: str, key: str) -> bool:
    try:
        ctx.client("s3").head_object(Bucket=bucket, Key=key)
        return True
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] in ("404", "NoSuchKey"):
            return False
        raise


def _zip_code(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-osbucket-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _caller_principal_arn(ctx) -> str:
    ident = ctx.client("sts").get_caller_identity()
    arn = ident["Arn"]
    if ":assumed-role/" in arn:
        parts = arn.split(":")
        account = parts[4]
        role_name = parts[5].split("/")[1]
        return f"arn:aws:iam::{account}:role/{role_name}"
    return arn


def _create_lambda_role(ctx, extra_statements: list[dict[str, Any]]) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-oslamrole-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )
    if extra_statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline-access",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": extra_statements}),
        )
    return role_name, role_arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_function(
    ctx, role_arn: str, source_code: str, env_vars: dict[str, str], timeout: int = 30
) -> dict[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-osfn-")
    zip_bytes = _zip_code(source_code)

    def _attempt():
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            return lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env_vars},
                Tags={"sim2real:managed": "true"},
            )
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                return None  # role not yet propagated through IAM; retry
            raise

    resp = _poll_until(
        _attempt, lambda r: r is not None, timeout_s=60, interval_s=3, description="lambda create_function (IAM propagation)"
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2,
        description="function Active",
    )
    return {"name": name, "arn": resp["FunctionArn"]}


def _add_s3_invoke_permission(ctx, function_name: str, bucket_name: str, account_id: str) -> None:
    ctx.client("lambda").add_permission(
        FunctionName=function_name,
        StatementId="AllowS3Invoke",
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceArn=f"arn:aws:s3:::{bucket_name}",
        SourceAccount=account_id,
    )


def _put_notification(
    ctx, bucket: str, function_arn: str, events: list[str], filter_rules: list[dict[str, str]] | None = None
) -> None:
    cfg: dict[str, Any] = {"LambdaFunctionArn": function_arn, "Events": events}
    if filter_rules:
        cfg["Filter"] = {"Key": {"FilterRules": filter_rules}}
    ctx.client("s3").put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"LambdaFunctionConfigurations": [cfg]}
    )


def _domain_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-os-").lower()
    raw = "".join(c for c in raw if c.isalnum() or c == "-")
    if not raw[0].isalpha():
        raw = "d" + raw
    return raw[:28].rstrip("-")


def _create_domain(ctx, allowed_principal_arns: list[str]) -> dict[str, str]:
    aos = ctx.client("opensearch")
    name = _domain_name(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    resource_pattern = f"arn:aws:es:{ctx.region}:{account_id}:domain/{name}/*"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": list(allowed_principal_arns)},
                "Action": "es:ESHttp*",
                "Resource": resource_pattern,
            }
        ],
    }
    aos.create_domain(
        DomainName=name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
        AccessPolicies=json.dumps(policy),
        NodeToNodeEncryptionOptions={"Enabled": True},
        EncryptionAtRestOptions={"Enabled": True},
        DomainEndpointOptions={"EnforceHTTPS": True},
    )
    ctx.on_cleanup(lambda: _delete_domain(ctx, name))
    aos.add_tags(
        ARN=f"arn:aws:es:{ctx.region}:{account_id}:domain/{name}",
        TagList=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    status = _poll_until(
        lambda: aos.describe_domain(DomainName=name)["DomainStatus"],
        lambda d: (not d.get("Processing", True)) and "Endpoint" in d,
        timeout_s=1800,
        interval_s=20,
        description=f"opensearch domain {name} active",
    )
    return {"name": name, "endpoint": status["Endpoint"], "arn": status["ARN"], "resource_pattern": resource_pattern}


def _delete_domain(ctx, name: str) -> None:
    try:
        ctx.client("opensearch").delete_domain(DomainName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _update_domain_access_policy(
    ctx, domain_name: str, resource_pattern: str, allowed_principal_arns: list[str]
) -> None:
    aos = ctx.client("opensearch")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": list(allowed_principal_arns)},
                "Action": "es:ESHttp*",
                "Resource": resource_pattern,
            }
        ],
    }
    aos.update_domain_config(DomainName=domain_name, AccessPolicies=json.dumps(policy))
    _poll_until(
        lambda: aos.describe_domain(DomainName=domain_name)["DomainStatus"]["Processing"],
        lambda p: p is False,
        timeout_s=600,
        interval_s=15,
        description=f"domain {domain_name} access-policy update applied",
    )


def _os_signed_request(ctx, endpoint: str, method: str, path: str, body: Any = None) -> tuple[int, Any]:
    creds = ctx.client("s3")._request_signer._credentials
    if hasattr(creds, "get_frozen_credentials"):
        creds = creds.get_frozen_credentials()
    url = f"{ctx.endpoint_url(endpoint)}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(creds, "es", ctx.region).add_auth(req)
    http_req = urllib.request.Request(url, data=req.body, headers=dict(req.headers), method=method)
    try:
        with urllib.request.urlopen(http_req, timeout=30) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"raw": raw.decode(errors="replace")}
        return e.code, parsed


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line, if it exists."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
