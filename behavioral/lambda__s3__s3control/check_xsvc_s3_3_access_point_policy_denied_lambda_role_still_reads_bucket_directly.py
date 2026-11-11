"""xsvc-s3-3-access-point-policy-denied-lambda-role-still-reads-bucket-directly."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-s3-3-access-point-policy-denied-lambda-role-still-reads-bucket-directly"
GROUP = "permission-chain"
SERVICES = ["lambda", "s3", "s3control"]

_KEY = "data/report.txt"
_BODY = "sim2real-xsvc-access-point-subject"

_HANDLER = """
import boto3

s3 = boto3.client("s3")


def lambda_handler(event, context):
    out = {}
    for label, bucket in event["paths"].items():
        try:
            resp = s3.get_object(Bucket=bucket, Key=event["key"])
            out[label] = {"body": resp["Body"].read().decode()}
        except Exception as exc:
            err = getattr(exc, "response", None) or {}
            out[label] = {
                "code": err.get("Error", {}).get("Code", type(exc).__name__),
                "message": err.get("Error", {}).get("Message", str(exc)),
            }
    return out
"""


# timing:real-time — ttl: 240 s
@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An access point policy Deny blocks a Lambda role via the AP while the bucket path serves it.
    The bucket delegates access control to its access points; the Deny beats the identity Allow.
    Deleting the AP policy then lets the same invocation read the bytes through the AP too.
    """
    s3 = ctx.client("s3")
    s3control = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _new_bucket(ctx)
    s3.put_object(Bucket=bucket, Key=_KEY, Body=_BODY.encode())

    ap_name = _xname(ctx, "ap")[:50]
    ap_arn = s3control.create_access_point(AccountId=account, Name=ap_name, Bucket=bucket)[
        "AccessPointArn"
    ]
    ctx.on_cleanup(lambda: s3control.delete_access_point(AccountId=account, Name=ap_name))

    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DelegateToAccessPoints",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "*",
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            "Condition": {"StringEquals": {"s3:DataAccessPointAccount": account}},
        }],
    }))

    fn = _create_lambda(ctx, _HANDLER, permissions=[{
        "Action": ["s3:GetObject"],
        "Resource": [f"arn:aws:s3:::{bucket}/*", f"{ap_arn}/object/*"],
    }])

    # The Deny names the role by condition rather than as Principal: S3 resolves a Principal ARN
    # to the role's unique id at write time, and a role created seconds ago is not yet resolvable.
    # aws:PrincipalArn of an assumed-role session is the ROLE arn (path included).
    deny = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyLambdaRole",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"{ap_arn}/object/*",
            "Condition": {"ArnEquals": {"aws:PrincipalArn": fn["role_arn"]}},
        }],
    }
    s3control.put_access_point_policy(AccountId=account, Name=ap_name, Policy=json.dumps(deny))
    stored = json.loads(s3control.get_access_point_policy(AccountId=account, Name=ap_name)["Policy"])
    assert stored["Statement"][0]["Effect"] == "Deny", f"the AP policy reads back as {stored!r}"

    event = {"key": _KEY, "paths": {"access_point": ap_arn, "bucket": bucket}}
    # The new role, its identity policy and the policies naming it all propagate; poll the
    # observable outcome (both arms settled) rather than sleeping. Bucket arm must serve bytes,
    # AP arm must be denied.
    denied = _poll_until(
        lambda: _invoke_payload(ctx, fn["name"], event),
        lambda r: r.get("bucket", {}).get("body") == _BODY
        and r.get("access_point", {}).get("code") == "AccessDenied",
        timeout_s=300.0,
        interval_s=5.0,
        description="AP arm AccessDenied while the bucket arm serves the object",
    )
    role_name = fn["role_arn"].split("/")[-1]
    denied_message = (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{fn['name']} is not authorized to "
        f"perform: s3:GetObject on resource: \"{ap_arn}/object/{_KEY}\" with an explicit deny in a "
        f"resource-based policy"
    )
    assert denied["access_point"] == {"code": "AccessDenied", "message": denied_message}, (
        f"reading through the access point whose policy denies the role returned "
        f"{denied['access_point']!r}, expected AccessDenied"
    )
    assert denied["bucket"] == {"body": _BODY}, (
        f"reading the same key by bucket name returned {denied['bucket']!r}; the AP policy must "
        "not govern the direct bucket path"
    )

    # Repair: remove the AP policy's Deny. Access through the AP now rests on the identity policy
    # plus the bucket's DataAccessPointAccount delegation alone. Same invocation, both arms.
    s3control.delete_access_point_policy(AccountId=account, Name=ap_name)
    gone, gone_message = _client_error_code(
        lambda: s3control.get_access_point_policy(AccountId=account, Name=ap_name)
    )
    # S3 caches an access point's policy from its first data access for about four minutes, so
    # the lifted Deny is polled for within a 300 s bound.
    assert gone == "NoSuchAccessPointPolicy", (
        f"GetAccessPointPolicy after DeleteAccessPointPolicy returned {gone!r}, expected NoSuchAccessPointPolicy"
    )
    assert gone_message == "The specified accesspoint policy does not exist", (
        f"unexpected GetAccessPointPolicy not-found message: {gone_message!r}"
    )
    repaired = _poll_until(
        lambda: _invoke_payload(ctx, fn["name"], event),
        lambda r: r.get("access_point", {}).get("body") == _BODY,
        timeout_s=300.0,
        interval_s=5.0,
        description="AP arm serves the object after the AP policy is repaired",
    )
    assert repaired == {"access_point": {"body": _BODY}, "bucket": {"body": _BODY}}, (
        f"after deleting the AP policy's Deny the two arms returned {repaired!r}; both must "
        "serve the identical object"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags():
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv():
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind):
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _client_error_code(fn):
    """Call fn(), which MUST fail; return its (code, message). Success is itself a failure."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("the call succeeded; real AWS rejects it")


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _reap_log_group(ctx, name):
    """delete_function leaves /aws/lambda/<fn>, and a late flush can recreate it: delete, then poll
    for reappearance over a bounded window. The execution role grants NO logs permission, so in
    practice the group is never created; this is the net for a target that creates it anyway."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{name}"
    deadline = time.monotonic() + 10.0
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if not any(g["logGroupName"] == group for g in found):
            if time.monotonic() >= deadline:
                return
        elif time.monotonic() >= deadline:
            raise RuntimeError(f"log group {group} still present after reap window")
        time.sleep(5)


def _create_lambda(ctx, handler_code, permissions):
    """Execution role with ONLY `permissions` (deliberately no CloudWatch Logs permission, so no
    log group can be created), then the function, retried through role propagation."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = _xname(ctx, "role")
    role = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", **p} for p in permissions],
        }),
    )
    name = _xname(ctx, "fn")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))  # registered BEFORE create: runs after delete
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))
    deadline = time.monotonic() + 90
    while True:
        try:
            resp = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role["Role"]["Arn"],
                Handler="lambda_function.lambda_handler", Code={"ZipFile": buf.getvalue()},
                Timeout=30, MemorySize=128, Tags=_xsvc_resource_tags(),
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() >= deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=90.0, interval_s=2.0, description=f"Lambda {name} Active",
    )
    return {"name": name, "arn": resp["FunctionArn"], "role_arn": role["Role"]["Arn"]}


def _invoke_payload(ctx, name, payload):
    resp = ctx.client("lambda").invoke(
        FunctionName=name, InvocationType="RequestResponse", Payload=json.dumps(payload).encode()
    )
    body = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"Invoke returned {resp['StatusCode']}: {body[:300]!r}"
    assert not resp.get("FunctionError"), f"handler faulted: {body[:500]!r}"
    return json.loads(body)


def _delete_bucket(s3, bucket):
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    s3.delete_bucket(Bucket=bucket)


def _new_bucket(ctx):
    s3 = ctx.client("s3")
    name = _xname(ctx, "bkt")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
