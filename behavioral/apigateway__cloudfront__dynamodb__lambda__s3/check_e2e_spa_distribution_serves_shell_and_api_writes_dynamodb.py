"""e2e-spa-distribution-serves-shell-and-api-writes-dynamodb."""
from __future__ import annotations

import io
import json
import time
import zipfile

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-spa-distribution-serves-shell-and-api-writes-dynamodb"
GROUP = "e2e"
SERVICES = ["apigateway", "cloudfront", "dynamodb", "lambda", "s3"]

#: Managed cache policy CachingDisabled and origin request policy AllViewerExceptHostHeader.
MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
MANAGED_ALL_VIEWER_EXCEPT_HOST = "b689b0a8-53d0-40ab-baf2-68738e2966ac"

#: How long a new distribution may take to reach Deployed, and its disable before delete.
DEPLOYED_TIMEOUT_S = 1200.0

STAGE = "prod"
API_PATH = "/aws-blocks/api"

INDEX_HTML = b"<!doctype html><html><body><div id=\"root\">sim2real spa shell</div></body></html>"
APP_JS = b"console.log('sim2real spa bundle');"
# An object stored under an extensionless key: served only if the viewer function did not rewrite.
DASHBOARD_OBJECT = b"sim2real object stored under the extensionless key dashboard"

# Rewrites every extensionless path except the root to the shell, as a single-page app router needs.
VIEWER_REQUEST_FUNCTION = b"""function handler(event) {
  var request = event.request;
  var uri = request.uri;
  var last = uri.substring(uri.lastIndexOf('/') + 1);
  if (uri !== '/' && last.indexOf('.') === -1) {
    request.uri = '/index.html';
  }
  return request;
}
"""

HANDLER_MJS = """import { DynamoDBClient, PutItemCommand, GetItemCommand } from "@aws-sdk/client-dynamodb";

const ddb = new DynamoDBClient({});

export const handler = async (event) => {
  const input = JSON.parse(event.body || "{}");
  const table = process.env.TABLE_NAME;
  await ddb.send(new PutItemCommand({
    TableName: table,
    Item: { pk: { S: input.id }, note: { S: input.note } },
  }));
  const got = await ddb.send(new GetItemCommand({
    TableName: table, Key: { pk: { S: input.id } }, ConsistentRead: true,
  }));
  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id: got.Item.pk.S,
      note: got.Item.note.S,
      path: event.path,
      method: event.httpMethod,
      stage: event.requestContext.stage,
    }),
  };
};
"""

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


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


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _partition(ctx) -> str:
    """The caller's partition, read off its own ARN, never a literal."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], "the caller's ARN does not parse"
    return parts[1]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Bounded retry that raises on timeout, quoting the last observation."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out waiting for {description} after {timeout_s:.0f}s (last: {last!r})")
        time.sleep(interval_s)


def _wait_deployed(cf, dist_id, timeout_s):
    _poll_until(lambda: cf.get_distribution(Id=dist_id)["Distribution"]["Status"],
                lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=5.0,
                description=f"distribution {dist_id} to reach Deployed")


def _disable_and_delete_distribution(cf, dist_id) -> None:
    """Disable, wait for that change to deploy, then delete."""
    try:
        resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg, etag = resp["DistributionConfig"], resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
    _wait_deployed(cf, dist_id, DEPLOYED_TIMEOUT_S)
    cf.delete_distribution(Id=dist_id, IfMatch=cf.get_distribution(Id=dist_id)["ETag"])


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]!r}")
    s3.delete_bucket(Bucket=bucket)


def _delete_rest_api(apigw, api_id) -> None:
    """DeleteRestApi is rate limited per account; retry only its throttle."""
    deadline = time.monotonic() + 120
    while True:
        try:
            apigw.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() > deadline:
                raise
            time.sleep(10)


def _create_bucket(ctx, s3, bucket) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _create_role(ctx, table_arn, part) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-spa-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=_TAGS)["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    basic = f"arn:{part}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=basic)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=basic),
                             "NoSuchEntity"))
    iam.put_role_policy(RoleName=name, PolicyName="table-access", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
                       "Resource": table_arn}]}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name,
                                                            PolicyName="table-access"),
                             "NoSuchEntity"))
    return arn


def _create_function(ctx, role_arn, table) -> tuple[str, str]:
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-xsvc-spa-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.mjs", HANDLER_MJS)
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    # A just-created role is not yet assumable by Lambda; CreateFunction says so until it is.
    deadline = time.monotonic() + 120
    while True:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="nodejs22.x", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": buf.getvalue()}, Timeout=15,
                MemorySize=256, Environment={"Variables": {"TABLE_NAME": table}},
                Tags={"sim2real": CHECK})["FunctionArn"]
            break
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = (err.get("Code") == "InvalidParameterValueException"
                           and err.get("Message") == _ROLE_NOT_READY)
            if not propagating or time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    _poll_until(lambda: lam.get_function_configuration(FunctionName=name)["State"],
                lambda s: s in ("Active", "Failed"), timeout_s=120, interval_s=2.0,
                description=f"function {name} to leave Pending")
    state = lam.get_function_configuration(FunctionName=name)["State"]
    assert state == "Active", f"the nodejs22.x function must become Active, got {state!r}"
    return name, arn


def _create_rest_api(ctx, fn_name, fn_arn, part) -> str:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-xsvc-spa-api-"),
                                   endpointConfiguration={"types": ["REGIONAL"]},
                                   tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(apigw, api_id))
    root = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    blocks = apigw.create_resource(restApiId=api_id, parentId=root, pathPart="aws-blocks")["id"]
    api = apigw.create_resource(restApiId=api_id, parentId=blocks, pathPart="api")["id"]
    apigw.put_method(restApiId=api_id, resourceId=api, httpMethod="POST",
                     authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=api, httpMethod="POST", type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=f"arn:{part}:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn_arn}/invocations")
    ctx.client("lambda").add_permission(
        FunctionName=fn_name, StatementId="rest-api-post", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:{part}:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/POST{API_PATH}")
    apigw.create_deployment(restApiId=api_id, stageName=STAGE)
    return api_id


def _post_until_ok(session, url, payload, *, timeout_s, verify):
    """POST until 200: role and policy propagation can fail the first invocations."""
    def probe():
        try:
            return session.post(url, json=payload, timeout=30, verify=verify)
        except requests.RequestException as exc:
            return exc

    return _poll_until(probe, lambda r: isinstance(r, requests.Response) and r.status_code == 200,
                       timeout_s=timeout_s, interval_s=5.0, description=f"200 from POST {url}")


def _assert_api_answer(resp, item_id, note, leg) -> None:
    assert resp.headers.get("content-type", "").startswith("application/json"), (
        f"{leg}: expected the function's application/json content type, got "
        f"{resp.headers.get('content-type')!r}")
    body = resp.json()
    expected = {"id": item_id, "note": note, "path": API_PATH, "method": "POST", "stage": STAGE}
    assert body == expected, f"{leg}: expected the item read back {expected!r}, got {body!r}"


def _assert_item_stored(ddb, table, item_id, note, leg) -> None:
    item = ddb.get_item(TableName=table, Key={"pk": {"S": item_id}},
                        ConsistentRead=True).get("Item")
    assert item == {"pk": {"S": item_id}, "note": {"S": note}}, (
        f"{leg}: the function's write must be in the table, got {item!r}")


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A single-page app on CloudFront serves its shell for /, rewritten routes and errors, and its
    /aws-blocks/* behavior reaches a REST API whose nodejs22.x proxy function writes and reads
    DynamoDB; the stage URL answers the same POST.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    ddb = ctx.client("dynamodb")

    table = ctx.unique_name("sim2real-xsvc-spa-tbl-")
    table_arn = ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        Tags=_TAGS)["TableDescription"]["TableArn"]
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table),
                             "ResourceNotFoundException"))

    bucket = ctx.unique_name("sim2real-xsvc-spa-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(_teardown(lambda: _empty_and_delete_bucket(s3, bucket), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})
    s3.put_object(Bucket=bucket, Key="index.html", Body=INDEX_HTML, ContentType="text/html")
    s3.put_object(Bucket=bucket, Key="app.js", Body=APP_JS, ContentType="text/javascript")
    s3.put_object(Bucket=bucket, Key="dashboard", Body=DASHBOARD_OBJECT,
                  ContentType="text/plain")

    ddb.get_waiter("table_exists").wait(TableName=table,
                                         WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    part = _partition(ctx)
    role_arn = _create_role(ctx, table_arn, part)
    fn_name, fn_arn = _create_function(ctx, role_arn, table)
    api_id = _create_rest_api(ctx, fn_name, fn_arn, part)

    fn_resp = cf.create_function(
        Name=ctx.unique_name("sim2real-xsvc-spa-rw-"),
        FunctionConfig={"Comment": "sim2real spa router", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=VIEWER_REQUEST_FUNCTION)
    cf_fn_name = fn_resp["FunctionSummary"]["Name"]
    ctx.on_cleanup(_teardown(
        lambda: cf.delete_function(Name=cf_fn_name,
                                   IfMatch=cf.describe_function(Name=cf_fn_name)["ETag"]),
        "NoSuchFunctionExists"))
    cf.publish_function(Name=cf_fn_name, IfMatch=fn_resp["ETag"])
    cf_fn_arn = cf.describe_function(Name=cf_fn_name, Stage="LIVE")["FunctionSummary"][
        "FunctionMetadata"]["FunctionARN"]

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-xsvc-spa-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(_teardown(
        lambda: cf.delete_origin_access_control(
            Id=oac_id, IfMatch=cf.get_origin_access_control(Id=oac_id)["ETag"]),
        "NoSuchOriginAccessControl"))

    all_methods = {"Quantity": 7,
                   "Items": ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"],
                   "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}}
    errors = [{"ErrorCode": code, "ResponsePagePath": "/index.html", "ResponseCode": "200",
               "ErrorCachingMinTTL": 0} for code in (403, 404)]
    dist = cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": {
            "CallerReference": ctx.unique_name("sim2real-xsvc-spa-cr-"),
            "Comment": "sim2real single-page app",
            "Enabled": True,
            "DefaultRootObject": "index.html",
            "PriceClass": "PriceClass_100",
            "Origins": {"Quantity": 2, "Items": [
                {"Id": "site", "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
                 "S3OriginConfig": {"OriginAccessIdentity": ""},
                 "OriginAccessControlId": oac_id},
                {"Id": "api", "DomainName": f"{api_id}.execute-api.{ctx.region}.amazonaws.com",
                 "OriginPath": f"/{STAGE}",
                 "CustomOriginConfig": {
                     "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only",
                     "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]}}},
            ]},
            "DefaultCacheBehavior": {
                "TargetOriginId": "site",
                "ViewerProtocolPolicy": "redirect-to-https",
                "CachePolicyId": MANAGED_CACHING_DISABLED,
                "FunctionAssociations": {"Quantity": 1, "Items": [
                    {"FunctionARN": cf_fn_arn, "EventType": "viewer-request"}]},
            },
            "CacheBehaviors": {"Quantity": 1, "Items": [{
                "PathPattern": "/aws-blocks/*",
                "TargetOriginId": "api",
                "ViewerProtocolPolicy": "https-only",
                "AllowedMethods": all_methods,
                "CachePolicyId": MANAGED_CACHING_DISABLED,
                "OriginRequestPolicyId": MANAGED_ALL_VIEWER_EXCEPT_HOST,
            }]},
            "CustomErrorResponses": {"Quantity": len(errors), "Items": errors},
        },
        "Tags": {"Items": _TAGS},
    })["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:{part}:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist["ARN"]}},
        }],
    }))

    session = requests.Session()

    # The stage URL first: the same POST a frontend dev server sends straight to the API.
    stage_id, stage_note = ctx.unique_name("stage-"), "written through the stage url"
    stage_resp = _post_until_ok(session, f"{ctx.api_url(api_id, STAGE)}{API_PATH}",
                                {"id": stage_id, "note": stage_note},
                                timeout_s=_budget_s(ctx, 180.0), verify=ctx.http_verify)
    _assert_api_answer(stage_resp, stage_id, stage_note, "stage url")
    _assert_item_stored(ddb, table, stage_id, stage_note, "stage url")

    _wait_deployed(cf, dist_id, _budget_s(ctx, DEPLOYED_TIMEOUT_S))
    edge = ctx.endpoint_url(dist["DomainName"])

    def get(path):
        try:
            return session.get(f"{edge}{path}", timeout=30, verify=ctx.http_verify)
        except requests.RequestException as exc:
            return exc

    root = _poll_until(lambda: get("/"),
                       lambda r: isinstance(r, requests.Response) and r.content == INDEX_HTML,
                       timeout_s=_budget_s(ctx, 180.0), description="the shell at /")
    assert root.status_code == 200, f"GET /: expected 200, got {root.status_code}"

    asset = get("/app.js")
    assert isinstance(asset, requests.Response) and asset.status_code == 200, (
        f"GET /app.js: a path with an extension is served as stored, got {asset!r}")
    assert asset.content == APP_JS, f"GET /app.js: expected {APP_JS!r}, got {asset.content[:200]!r}"

    for route in ("/dashboard", "/settings/profile"):
        page = get(route)
        assert isinstance(page, requests.Response) and page.status_code == 200, (
            f"GET {route}: the viewer-request function rewrites it to the shell, got {page!r}")
        assert page.content == INDEX_HTML, (
            f"GET {route}: expected the shell {INDEX_HTML!r}, got {page.content[:200]!r}")

    missing = get("/assets/missing.js")
    assert isinstance(missing, requests.Response) and missing.status_code == 200, (
        f"GET /assets/missing.js: the origin's error becomes the shell with ResponseCode 200, "
        f"got {missing!r}")
    assert missing.content == INDEX_HTML, (
        f"GET /assets/missing.js: expected the shell as the custom error page, got "
        f"{missing.content[:200]!r}")

    edge_id, edge_note = ctx.unique_name("edge-"), "written through the distribution"
    edge_resp = _post_until_ok(session, f"{edge}{API_PATH}", {"id": edge_id, "note": edge_note},
                               timeout_s=_budget_s(ctx, 120.0), verify=ctx.http_verify)
    _assert_api_answer(edge_resp, edge_id, edge_note, "distribution")
    _assert_item_stored(ddb, table, edge_id, edge_note, "distribution")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
