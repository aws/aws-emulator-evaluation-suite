"""cloudfront-apigw-origin-protocol-mismatch-negative."""
from __future__ import annotations

import io
import json
import ssl
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cloudfront-apigw-origin-protocol-mismatch-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cloudfront", "s3"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Two cache behaviors reach the same API Gateway REST API through an https-only and an
    http-only origin: the https-only one delivers the API's response, the http-only one surfaces
    an origin error to the viewer, since API Gateway never serves plaintext HTTP."""
    role_arn = _create_lambda_role(ctx)
    lambda_arn, lambda_name = _create_echo_lambda(ctx, role_arn, "protocol-mismatch")
    api = _create_proxy_rest_api(ctx, lambda_arn, lambda_name)

    ok_origin_id, broken_origin_id = "ok-origin", "broken-origin"
    ok_origin = _build_custom_origin(ok_origin_id, api["domain"], f"/{api['stage']}", "https-only")
    broken_origin = _build_custom_origin(broken_origin_id, api["domain"], f"/{api['stage']}", "http-only")

    dist = _create_distribution(
        ctx,
        [ok_origin, broken_origin],
        ok_origin_id,
        cache_behaviors=[{"pattern": "broken/*", "origin_id": broken_origin_id}],
    )
    _wait_distribution_deployed(ctx, dist["id"])

    # --- positive control: the SAME distribution, at the SAME instant, must actually deliver the
    # API's response over the https-only origin. Without this leg, a distribution whose origin
    # fetch is broken for every path (a bad integration, a missing invoke permission, a wrong
    # domain) would ALSO answer every request to the http-only origin with 502/504 -- indistinguishable
    # from correctly enforcing the protocol mismatch. This rules that out on the same wiring.
    def _ok_delivered(status, _headers, body):
        if status != 200:
            return False
        try:
            payload = json.loads(body)
        except ValueError:
            return False
        return payload.get("origin_label") == "protocol-mismatch"

    edge, edge_headers = ctx.endpoint_route(dist["domain"])
    cb1 = ctx.unique_name("cb-")
    status_ok, _, body_ok = _poll_get(
        f"{edge}/probe?cb={cb1}", headers=edge_headers, predicate=_ok_delivered, timeout_s=240, interval_s=10, verify=ctx.http_verify,
    )
    payload_ok = json.loads(body_ok)
    assert status_ok == 200, f"positive control: https-only origin must deliver 200, got {status_ok}"
    assert payload_ok.get("origin_label") == "protocol-mismatch", (
        f"positive control: expected origin_label 'protocol-mismatch' from the https-only origin, "
        f"got {payload_ok!r}"
    )

    # --- break exactly one thing: force CloudFront to connect over plaintext HTTP to the same origin ---
    # CloudFront surfaces a failed/refused origin connection as a 502 (Bad Gateway) or a 504
    # (Gateway Timeout) depending on whether the far end actively refuses or the connect stalls --
    # either way the origin request never got an HTTP response to relay to the viewer.
    def _origin_connect_failed(status, _headers, _body):
        return status in (502, 504)

    cb2 = ctx.unique_name("cb-")
    status, _, body = _poll_get(
        f"{edge}/broken/probe?cb={cb2}", headers=edge_headers, predicate=_origin_connect_failed, timeout_s=90,
        interval_s=5, verify=ctx.http_verify,
    )
    assert status in (502, 504), f"expected origin-connect failure (502/504) from the http-only origin, got {status}"
    # effect is absent: the API's response never reached the viewer over the downgraded connection
    assert b"origin_label" not in body, f"origin response leaked through the downgraded http-only connection: {body!r}"



# ===== helpers =====


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cfagw-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _lambda_zip_bytes():
    code = (
        "import json\n"
        "import os\n\n"
        "def handler(event, context):\n"
        "    headers = event.get('headers') or {}\n"
        "    body = {\n"
        "        'origin_label': os.environ.get('ORIGIN_LABEL', ''),\n"
        "        'headers': headers,\n"
        "        'path': event.get('path'),\n"
        "    }\n"
        "    return {\n"
        "        'statusCode': 200,\n"
        "        'headers': {'Content-Type': 'application/json'},\n"
        "        'body': json.dumps(body),\n"
        "    }\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_echo_lambda(ctx, role_arn, label):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-cfagw-fn-")
    zip_bytes = _lambda_zip_bytes()

    deadline = time.monotonic() + 90
    resp = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=10,
                Environment={"Variables": {"ORIGIN_LABEL": label}},
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(5)
    if resp is None:
        raise AssertionError(f"create_function never succeeded (IAM role propagation?): {last_exc}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))

    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=name)["Configuration"]["State"]
        if state == "Active":
            break
        time.sleep(3)
    else:
        raise AssertionError("lambda function never became Active")

    return resp["FunctionArn"], name


def _create_proxy_rest_api(ctx, lambda_arn, lambda_name):
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    api_name = ctx.unique_name("sim2real-cfagw-api-")
    api = apigw.create_rest_api(
        name=api_name, endpointConfiguration={"types": ["REGIONAL"]}, tags={"sim2real": CHECK}
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    proxy = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="{proxy+}")
    proxy_id = proxy["id"]

    uri = f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations"
    for resource_id in (root_id, proxy_id):
        apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="ANY", authorizationType="NONE")
        apigw.put_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="ANY",
            type="AWS_PROXY",
            integrationHttpMethod="POST",
            uri=uri,
        )

    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=lambda_name,
        StatementId=ctx.unique_name("cfagw-perm-"),
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{region}:{account_id}:{api_id}/*/*/*",
    )

    stage_name = "test"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    domain = f"{api_id}.execute-api.{region}.amazonaws.com"
    return {"api_id": api_id, "domain": domain, "stage": stage_name, "account_id": account_id, "region": region}


def _build_custom_origin(origin_id, domain, origin_path, protocol_policy, custom_headers=None):
    origin = {
        "Id": origin_id,
        "DomainName": domain,
        "OriginPath": origin_path,
        "CustomOriginConfig": {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": protocol_policy,
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            "OriginReadTimeout": 30,
            "OriginKeepaliveTimeout": 5,
        },
    }
    if custom_headers:
        origin["OriginCustomHeaders"] = {
            "Quantity": len(custom_headers),
            "Items": [{"HeaderName": k, "HeaderValue": v} for k, v in custom_headers.items()],
        }
    return origin


def _create_distribution(ctx, origins, default_origin_id, cache_behaviors=None, forward_headers=None):
    cf = ctx.client("cloudfront")
    ref = ctx.unique_name("sim2real-cfagw-dist-")

    headers_cfg = {"Quantity": 0}
    if forward_headers:
        headers_cfg = {"Quantity": len(forward_headers), "Items": list(forward_headers)}

    allowed_methods = {
        "Quantity": 7,
        "Items": ["GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS", "DELETE"],
        "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
    }

    behavior_items = []
    for cb in cache_behaviors or []:
        behavior_items.append(
            {
                "PathPattern": cb["pattern"],
                "TargetOriginId": cb["origin_id"],
                "ViewerProtocolPolicy": "allow-all",
                "AllowedMethods": allowed_methods,
                "ForwardedValues": {
                    "QueryString": True,
                    "Cookies": {"Forward": "none"},
                    "Headers": headers_cfg,
                },
                "MinTTL": 0,
                "DefaultTTL": 0,
                "MaxTTL": 0,
            }
        )

    config = {
        "CallerReference": ref,
        "Comment": ref,
        "Enabled": True,
        "Origins": {"Quantity": len(origins), "Items": origins},
        "DefaultCacheBehavior": {
            "TargetOriginId": default_origin_id,
            "ViewerProtocolPolicy": "allow-all",
            "AllowedMethods": allowed_methods,
            "ForwardedValues": {
                "QueryString": True,
                "Cookies": {"Forward": "none"},
                "Headers": headers_cfg,
            },
            "MinTTL": 0,
            "DefaultTTL": 0,
            "MaxTTL": 0,
        },
        "CacheBehaviors": {"Quantity": len(behavior_items), "Items": behavior_items},
    }

    resp = cf.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    dist_arn = resp["Distribution"]["ARN"]
    domain = resp["Distribution"]["DomainName"]
    cf.tag_resource(Resource=dist_arn, Tags={"Items": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return {"id": dist_id, "domain": domain}


def _delete_distribution(ctx, dist_id):
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    etag = cfg_resp["ETag"]
    dist_config = cfg_resp["DistributionConfig"]
    if dist_config.get("Enabled"):
        dist_config["Enabled"] = False
        upd = cf.update_distribution(Id=dist_id, DistributionConfig=dist_config, IfMatch=etag)
        etag = upd["ETag"]
    # Disabling a distribution deploys in minutes; 1500 s leaves the rest of the teardown room.
    waiter = cf.get_waiter("distribution_deployed")
    waiter.wait(Id=dist_id, WaiterConfig={"Delay": 2, "MaxAttempts": 750})
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"])


def _wait_distribution_deployed(ctx, dist_id, max_attempts=80, delay=30):
    cf = ctx.client("cloudfront")
    waiter = cf.get_waiter("distribution_deployed")
    waiter.wait(Id=dist_id, WaiterConfig={"Delay": delay, "MaxAttempts": max_attempts})


def _http_get(url, headers=None, timeout=15, verify=True):
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_https_context(verify)) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        hdrs = {k.lower(): v for k, v in (exc.headers or {}).items()} if exc.headers else {}
        return exc.code, hdrs, exc.read()


def _poll_get(url, headers=None, predicate=None, timeout_s=180, interval_s=8, verify=True):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            status, resp_headers, body = _http_get(url, headers=headers, verify=verify)
            last = (status, resp_headers, body)
            if predicate is None or predicate(status, resp_headers, body):
                return status, resp_headers, body
        except Exception as exc:
            last = exc
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied for {url} within {timeout_s}s (last={last!r})")


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _https_context(verify) -> ssl.SSLContext:
    """The TLS context http.client builds by default, verifying with ``ctx.http_verify``."""
    if verify is False:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(cafile=verify if isinstance(verify, str) and verify else None)
    context.set_alpn_protocols(["http/1.1"])
    if context.post_handshake_auth is not None:
        context.post_handshake_auth = True
    return context


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
