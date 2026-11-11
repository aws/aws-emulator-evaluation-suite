"""deploy-s3-notification-lambda-opensearch-pipeline-positive."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

import botocore.auth
import botocore.awsrequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-s3-notification-lambda-opensearch-pipeline-positive"
GROUP = "deployment-order"
SERVICES = ["lambda", "opensearch", "s3"]

_OS_INDEX = "documents"

_LAMBDA_CODE = """
import boto3, botocore.auth, botocore.awsrequest, json, os
import urllib.parse, urllib.request, urllib.error

s3 = boto3.client("s3")


def handler(event, context):
    creds = boto3.Session().get_credentials().get_frozen_credentials()
    host = os.environ["OS_HOST"]
    region = os.environ["AWS_REGION"]
    index = os.environ["OS_INDEX"]
    out = []
    for rec in event.get("Records", []):
        bucket = rec["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(rec["s3"]["object"]["key"])
        obj = s3.get_object(Bucket=bucket, Key=key)
        doc = json.loads(obj["Body"].read())
        docid = key.replace("/", "_")
        url = "https://%s/%s/_doc/%s" % (host, index, docid)
        data = json.dumps(doc).encode()
        req = botocore.awsrequest.AWSRequest(
            method="PUT", url=url, data=data,
            headers={"Content-Type": "application/json"},
        )
        botocore.auth.SigV4Auth(creds, "es", region).add_auth(req)
        p = req.prepare()
        try:
            r = urllib.request.Request(p.url, data=data, headers=dict(p.headers), method="PUT")
            with urllib.request.urlopen(r, timeout=10) as resp:
                out.append({"key": key, "status": resp.status})
        except urllib.error.HTTPError as e:
            out.append({"key": key, "status": e.code, "error": e.read().decode()})
    return {"results": out}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The deployed S3 notification config targets the Lambda function with a suffix filter
    (".json" only): matching uploads get indexed into OpenSearch, non-matching ones don't."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket_name = _xname(ctx, "bkt").lower()
    domain_name = _domain_name(ctx)
    function_name = _xname(ctx, "fn")
    role_name = _xname(ctx, "role")

    template = _build_template(
        region=ctx.region,
        account_id=account_id,
        bucket_name=bucket_name,
        domain_name=domain_name,
        function_name=function_name,
        role_name=role_name,
        access_principal="lambda-role",
        with_notification=True,
        notification_suffix=".json",
    )

    _deploy_cfn(ctx, template, timeout_s=1800.0)
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))

    s3 = ctx.client("s3")
    same_doc = {"id": "match-or-not", "note": "identical content, different suffix"}

    match_key = "feed/keep.json"
    skip_key = "feed/skip.log"
    s3.put_object(Bucket=bucket_name, Key=match_key, Body=json.dumps(same_doc).encode())
    s3.put_object(Bucket=bucket_name, Key=skip_key, Body=json.dumps(same_doc).encode())

    domain = ctx.client("opensearch").describe_domain(DomainName=domain_name)["DomainStatus"]
    host = domain["Endpoint"]
    match_doc_id = match_key.replace("/", "_")
    skip_doc_id = skip_key.replace("/", "_")

    status, body = _poll_until(
        lambda: _os_request(ctx, "GET", host, f"/{_OS_INDEX}/_doc/{match_doc_id}"),
        lambda r: r[0] == 200,
        timeout_s=120.0,
        interval_s=5.0,
        description=f"indexed document for matching suffix ({match_key})",
    )
    assert status == 200, f"expected 200 for indexed matching-suffix doc {match_key}, got {status}: {body!r}"
    assert body["_source"] == same_doc, f"expected indexed _source {same_doc!r}, got {body.get('_source')!r}"

    # Same content, non-matching suffix, equal (or more) time to be (wrongly) delivered too:
    # it must still be absent -- proves the notification Filter, not just eventual laziness.
    skip_status, skip_body = _os_request(ctx, "GET", host, f"/{_OS_INDEX}/_doc/{skip_doc_id}")
    assert skip_status == 404 and skip_body.get("found") is False, (
        f"suffix filter should have excluded {skip_key}, got {skip_status}: {skip_body!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
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


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _domain_name(ctx: Any) -> str:
    tail = ctx.unique_name("x")[-20:].lower()
    cleaned = "".join(c for c in tail if c.isalnum() or c == "-").strip("-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "o" + cleaned
    return cleaned[:28] or "osdomain2"


def _empty_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _os_request(ctx, method: str, host: str, path: str, body: Any = None):
    creds = ctx.client("s3")._request_signer._credentials.get_frozen_credentials()
    url = f"{ctx.endpoint_url(host)}{path}"
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = botocore.awsrequest.AWSRequest(method=method, url=url, data=data, headers=headers)
    botocore.auth.SigV4Auth(creds, "es", ctx.region).add_auth(req)
    prepped = req.prepare()
    http_req = urllib.request.Request(prepped.url, data=data, headers=dict(prepped.headers), method=method)
    try:
        with urllib.request.urlopen(http_req, timeout=15) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"raw": raw.decode(errors="replace")}
        return exc.code, parsed
    except urllib.error.URLError:
        return 0, {}


def _build_template(
    *,
    region: str,
    account_id: str,
    bucket_name: str,
    domain_name: str,
    function_name: str,
    role_name: str,
    access_principal: str,
    with_notification: bool,
    notification_suffix: str | None = None,
    extra_role_policies: list[dict[str, Any]] | None = None,
) -> str:
    domain_arn = f"arn:aws:es:{region}:{account_id}:domain/{domain_name}"
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    policies = [
        {
            "PolicyName": "base-access",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "*",
                    },
                    {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"{bucket_arn}/*"},
                ],
            },
        }
    ]
    for extra in extra_role_policies or []:
        policies.append(
            {
                "PolicyName": extra["name"],
                "PolicyDocument": {"Version": "2012-10-17", "Statement": extra["statements"]},
            }
        )

    principal_arns = (
        [{"Fn::GetAtt": ["IndexerRole", "Arn"]}]
        if access_principal == "lambda-role"
        else [access_principal]
    )

    resources: dict[str, Any] = {
        "IndexerRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "Policies": policies,
            },
        },
        "OpenSearchDomain": {
            "Type": "AWS::OpenSearchService::Domain",
            "Properties": {
                "DomainName": domain_name,
                "EngineVersion": "OpenSearch_2.11",
                "ClusterConfig": {
                    "InstanceType": "t3.small.search",
                    "InstanceCount": 1,
                    "DedicatedMasterEnabled": False,
                    "ZoneAwarenessEnabled": False,
                },
                "EBSOptions": {"EBSEnabled": True, "VolumeSize": 10, "VolumeType": "gp3"},
                "AccessPolicies": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": principal_arns},
                            "Action": "es:ESHttp*",
                            "Resource": f"{domain_arn}/*",
                        }
                    ],
                },
            },
        },
        "IndexerFunction": {
            "Type": "AWS::Lambda::Function",
            "DependsOn": ["IndexerRole", "OpenSearchDomain"],
            "Properties": {
                "FunctionName": function_name,
                "Runtime": "python3.12",
                "Handler": "index.handler",
                "Timeout": 30,
                "MemorySize": 256,
                "Role": {"Fn::GetAtt": ["IndexerRole", "Arn"]},
                "Environment": {
                    "Variables": {
                        "OS_HOST": {"Fn::GetAtt": ["OpenSearchDomain", "DomainEndpoint"]},
                        "OS_INDEX": _OS_INDEX,
                    }
                },
                "Code": {"ZipFile": _LAMBDA_CODE},
            },
        },
    }

    if with_notification:
        resources["BucketPermission"] = {
            "Type": "AWS::Lambda::Permission",
            "DependsOn": "IndexerFunction",
            "Properties": {
                "FunctionName": {"Ref": "IndexerFunction"},
                "Action": "lambda:InvokeFunction",
                "Principal": "s3.amazonaws.com",
                "SourceArn": bucket_arn,
                "SourceAccount": account_id,
            },
        }
        lambda_config: dict[str, Any] = {
            "Event": "s3:ObjectCreated:*",
            "Function": {"Fn::GetAtt": ["IndexerFunction", "Arn"]},
        }
        if notification_suffix:
            lambda_config["Filter"] = {
                "S3Key": {"Rules": [{"Name": "suffix", "Value": notification_suffix}]}
            }
        resources["DataBucket"] = {
            "Type": "AWS::S3::Bucket",
            "DependsOn": "BucketPermission",
            "Properties": {
                "BucketName": bucket_name,
                "NotificationConfiguration": {"LambdaConfigurations": [lambda_config]},
            },
        }
    else:
        resources["DataBucket"] = {
            "Type": "AWS::S3::Bucket",
            "Properties": {"BucketName": bucket_name},
        }

    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete the stack and wait up to 1500 s of the 1800 s teardown budget for DELETE_COMPLETE: the
    OpenSearch domain delete takes minutes. Raises after."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=1500,
        interval_s=10.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if hasattr(template, "read_text") else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=10.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
