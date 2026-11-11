"""lambda-sdk-opensearch-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-opensearch-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "opensearch", "s3"]


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A Lambda role with only es:ESHttpGet gets 403 on a write that never lands, while a role with
    the write permission succeeds; granting the action in the restricted role's own identity policy
    (domain access policy untouched) then makes the identical write succeed."""
    account = _account_id(ctx)
    domain_name = _domain_name(ctx)
    domain_arn = f"arn:aws:es:{ctx.region}:{account}:domain/{domain_name}"
    resource = f"{domain_arn}/*"

    # The domain access policy only ever mentions control_role (satisfying the requirement
    # that a public, non-FGAC domain access policy contain a principal restriction).
    # restricted_role is never mentioned in it, so per AWS's own policy-collision table
    # (https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ac.html#ac-types-resource,
    # "When policies collide") an unmentioned principal's access is governed purely by its
    # own identity-based (IAM) policy -- which is exactly the boundary this check isolates.
    control_role = _create_lambda_role(ctx, [{"Effect": "Allow", "Action": "es:ESHttp*", "Resource": resource}])
    restricted_role = _create_lambda_role(ctx, [{"Effect": "Allow", "Action": "es:ESHttpGet", "Resource": resource}])

    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": control_role["arn"]},
                "Action": "es:ESHttp*",
                "Resource": resource,
            }
        ],
    }
    domain = _create_domain(ctx, domain_name, access_policy)
    endpoint = ctx.endpoint_url(domain["endpoint"])
    index = "sim2real-perm"

    control_fn = _create_lambda_function(ctx, control_role["arn"])
    restricted_fn = _create_lambda_function(ctx, restricted_role["arn"])

    # Positive control: the fully-permissioned role can write.
    baseline = _invoke(
        ctx,
        control_fn,
        {"endpoint": endpoint, "method": "PUT", "path": f"/{index}/_doc/baseline?refresh=true", "body": {"seed": True}},
    )
    assert baseline["statusCode"] in (200, 201), baseline

    # Break exactly one thing: attempt the same kind of write with the role that lacks
    # es:ESHttpPut/Post in its identity policy.
    blocked = _invoke(
        ctx,
        restricted_fn,
        {
            "endpoint": endpoint,
            "method": "PUT",
            "path": f"/{index}/_doc/blocked-write?refresh=true",
            "body": {"should": "not-write"},
        },
    )
    assert blocked["statusCode"] == 403, blocked

    # Effect absent: the blocked write never landed (verified via the permitted control role).
    absent = _invoke(ctx, control_fn, {"endpoint": endpoint, "method": "GET", "path": f"/{index}/_doc/blocked-write"})
    assert absent["statusCode"] == 404, absent

    # Positive control (same restricted role, its one granted action still works): proves the
    # restricted role isn't just universally rejected -- only the missing action is blocked.
    control_read = _invoke(
        ctx, restricted_fn, {"endpoint": endpoint, "method": "GET", "path": f"/{index}/_doc/baseline"}
    )
    assert control_read["statusCode"] == 200, control_read
    assert json.loads(control_read["body"])["_source"] == {"seed": True}, control_read

    # Restore: grant the restricted role the missing write action on its own identity policy
    # only (the domain access policy is never touched) -- the identical write now lands.
    _grant_es_action(ctx, restricted_role["name"], resource)
    restored = _poll_until_write_succeeds(
        ctx, restricted_fn, endpoint, index, "blocked-write", {"should": "not-write"}, timeout_s=900.0, interval_s=15.0
    )
    assert restored["statusCode"] in (200, 201), restored

    landed = _invoke(ctx, control_fn, {"endpoint": endpoint, "method": "GET", "path": f"/{index}/_doc/blocked-write"})
    assert landed["statusCode"] == 200, landed
    assert json.loads(landed["body"])["_source"] == {"should": "not-write"}, landed


# ===== helpers =====

_LAMBDA_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}

_LAMBDA_CODE = """
import json
import os
import urllib.error
import urllib.request

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest


def handler(event, context):
    region = os.environ["AWS_REGION"]
    endpoint = event["endpoint"].rstrip("/")
    path = event.get("path", "/")
    method = event.get("method", "GET")
    body = event.get("body")
    raw_body = event.get("raw_body")
    if raw_body is not None:
        data = raw_body.encode("utf-8")
    elif body is not None:
        data = json.dumps(body).encode("utf-8")
    else:
        data = b""
    session = boto3.Session()
    creds = session.get_credentials().get_frozen_credentials()
    url = endpoint + path
    headers = {"Content-Type": "application/json"} if data else {}
    signed = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(creds, "es", region).add_auth(signed)
    signed_headers = dict(signed.headers.items())
    http_req = urllib.request.Request(url, data=data if data else None, headers=signed_headers, method=method)
    try:
        with urllib.request.urlopen(http_req, timeout=25) as resp:
            return {"statusCode": resp.status, "body": resp.read().decode("utf-8")}
    except urllib.error.HTTPError as exc:
        return {"statusCode": exc.code, "body": exc.read().decode("utf-8")}
"""


_TAG = [{"Key": "sim2real", "Value": "lambda-sdk-opensearch-missing-permission-negative"}]


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _domain_name(ctx) -> str:
    name = ctx.unique_name("sim2real-osx-").lower()
    name = "".join(c for c in name if c.isalnum() or c == "-").strip("-")
    return name[:28]


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _create_domain(ctx, name: str, access_policy: dict) -> dict:
    client = ctx.client("opensearch")
    kwargs = dict(
        DomainName=name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=json.dumps(access_policy),
        TagList=_TAG,
    )
    # The access policy references an IAM role that was just created; OpenSearch's
    # policy-principal validation can lag IAM propagation, so retry on that specific
    # failure rather than the role's own permissions.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            client.create_domain(**kwargs)
            break
        except client.exceptions.InvalidTypeException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5.0)
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_domain(DomainName=name)))
    endpoint = _wait_for_domain_active(ctx, name, timeout_s=1800.0, interval_s=30.0)
    return {"name": name, "endpoint": endpoint}


def _wait_for_domain_active(ctx, name: str, timeout_s: float = 1800.0, interval_s: float = 30.0) -> str:
    client = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = client.describe_domain(DomainName=name)["DomainStatus"]
        if not status.get("Processing", True) and status.get("Endpoint"):
            return status["Endpoint"]
        time.sleep(interval_s)
    raise AssertionError(f"opensearch domain {name} did not become active within {timeout_s}s")


def _create_lambda_role(ctx, es_statements: list[dict]) -> dict:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-osrole-")
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST_POLICY), Tags=_TAG
    )["Role"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=name)))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=basic_policy_arn)))
    if es_statements:
        doc = {"Version": "2012-10-17", "Statement": es_statements}
        iam.put_role_policy(RoleName=name, PolicyName="es-access", PolicyDocument=json.dumps(doc))
        ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=name, PolicyName="es-access")))
    return {"name": name, "arn": role["Arn"]}


def _grant_es_action(ctx, role_name: str, resource: str) -> None:
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "es:ESHttp*", "Resource": resource}]}
    ctx.client("iam").put_role_policy(RoleName=role_name, PolicyName="es-access", PolicyDocument=json.dumps(doc))


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda_function(ctx, role_arn: str) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-osfn-")
    code = _zip_code(_LAMBDA_CODE)
    last_err = None
    ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code},
                Timeout=30,
                MemorySize=256,
                Tags={t["Key"]: t["Value"] for t in _TAG},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"create_function never succeeded (role propagation?): {last_err}"
                ) from exc
            time.sleep(2.0)
    ctx.on_cleanup(lambda: _safe(lambda: lam.delete_function(FunctionName=name)))
    _wait_for_function_active(ctx, name)
    return name


def _wait_for_function_active(ctx, name: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"lambda function {name} never became Active")


def _invoke(ctx, function_name: str, payload: dict) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode("utf-8"))
    raw = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation failed: {raw!r}")
    return json.loads(raw)


def _poll_until_write_succeeds(
    ctx, fn: str, endpoint: str, index: str, doc_id: str, body: dict, timeout_s: float = 120.0, interval_s: float = 5.0
) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = _invoke(
            ctx, fn, {"endpoint": endpoint, "method": "PUT", "path": f"/{index}/_doc/{doc_id}?refresh=true", "body": body}
        )
        if last["statusCode"] in (200, 201):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"write never succeeded after granting the missing identity-policy action: {last}")


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
