"""http-data-source-sigv4-signing-toggles-backend-authorization."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any

from behavioral_harness import tags

CHECK = "http-data-source-sigv4-signing-toggles-backend-authorization"
GROUP = "data-source"
SERVICES = ["appsync", "iam"]

SCHEMA = """
type BackendResponse {
    statusCode: Int
    body: String
}
type Query {
    signedCall: BackendResponse
    unsignedCall: BackendResponse
}
schema {
    query: Query
}
"""

REQUEST_TPL = """
{
  "version": "2018-05-29",
  "method": "GET",
  "resourcePath": "/",
  "params": {
    "query": {
      "Action": "GetCallerIdentity",
      "Version": "2011-06-15"
    }
  }
}
"""

RESPONSE_TPL = """
{
  "statusCode": $ctx.result.statusCode,
  "body": $util.toJson($ctx.result.body)
}
"""

QUERY_SIGNED = "{ signedCall { statusCode body } }"
QUERY_UNSIGNED = "{ unsignedCall { statusCode body } }"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx: Any) -> None:
    """An HTTP data source signs its backend request with the service role's SigV4 credentials
    only when `authorizationConfig` is set; the identical call with no config reaches the
    backend unsigned and is refused by it.
    """
    role_arn, role_name = _create_appsync_sts_role(ctx)

    api = _create_graphql_api(ctx)
    api_key = _create_api_key(ctx, api["apiId"])
    _deploy_schema(ctx, api["apiId"], SCHEMA)

    endpoint = "https://sts.us-west-2.amazonaws.com"
    signed_ds = _create_http_datasource(
        ctx,
        api["apiId"],
        endpoint,
        service_role_arn=role_arn,
        authorization_config={
            "authorizationType": "AWS_IAM",
            "awsIamConfig": {"signingRegion": ctx.region, "signingServiceName": "sts"},
        },
    )
    unsigned_ds = _create_http_datasource(ctx, api["apiId"], endpoint)
    _create_unit_resolver(ctx, api["apiId"], "Query", "signedCall", signed_ds, REQUEST_TPL, RESPONSE_TPL)
    _create_unit_resolver(ctx, api["apiId"], "Query", "unsignedCall", unsigned_ds, REQUEST_TPL, RESPONSE_TPL)

    headers = {"x-api-key": api_key}

    signed_resp = _poll_until(
        lambda: _graphql_request(ctx, api["endpoint"], headers, QUERY_SIGNED),
        lambda r: not r.get("errors") and (r.get("data") or {}).get("signedCall"),
        timeout_s=60.0,
    )
    assert signed_resp is not None and not signed_resp.get("errors"), f"signedCall query failed: {signed_resp}"
    signed = signed_resp["data"]["signedCall"]
    assert signed["statusCode"] == 200, f"a signed backend call expected statusCode 200, got {signed['statusCode']!r}"
    arn = _parse_caller_identity_arn(signed["body"])
    expected_prefix = f"arn:aws:sts::{ctx.account}:assumed-role/{role_name}/"
    assert arn.startswith(expected_prefix), f"signed call's own identity {arn!r} does not start with {expected_prefix!r}"

    unsigned_resp = _graphql_request(ctx, api["endpoint"], headers, QUERY_UNSIGNED)
    assert not unsigned_resp.get("errors"), f"unsignedCall query failed: {unsigned_resp}"
    unsigned = unsigned_resp["data"]["unsignedCall"]
    assert unsigned["statusCode"] == 403, f"an unsigned backend call expected statusCode 403, got {unsigned['statusCode']!r}"
    unsigned_error = _parse_sts_error(unsigned["body"])
    assert unsigned_error == ("Sender", "MissingAuthenticationToken", "Request is missing Authentication Token"), (
        f"unexpected unsigned call error {unsigned_error!r}"
    )


def _parse_caller_identity_arn(body: str) -> str:
    root = ET.fromstring(body)
    ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
    arn = root.findtext(f"{ns}GetCallerIdentityResult/{ns}Arn")
    assert arn, f"no Arn element in GetCallerIdentity body: {body!r}"
    return arn


def _parse_sts_error(body: str) -> tuple[str, str, str]:
    """(Type, Code, Message) from an STS ErrorResponse XML body, ignoring RequestId."""
    root = ET.fromstring(body)
    ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
    error = root.find(f"{ns}Error")
    assert error is not None, f"no <Error> element in body: {body!r}"
    return (
        error.findtext(f"{ns}Type"),
        error.findtext(f"{ns}Code"),
        error.findtext(f"{ns}Message"),
    )


def _create_appsync_sts_role(ctx: Any) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-appsync-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "appsync.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Arn"], role_name


def _create_graphql_api(ctx: Any) -> dict[str, str]:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-appsync-api-")
    resp = appsync.create_graphql_api(
        name=name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api = resp["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return {"apiId": api_id, "endpoint": api["uris"]["GRAPHQL"]}


def _create_api_key(ctx: Any, api_id: str) -> str:
    appsync = ctx.client("appsync")
    return appsync.create_api_key(apiId=api_id)["apiKey"]["id"]


def _deploy_schema(ctx: Any, api_id: str, sdl: str, timeout_s: float = 60.0) -> None:
    appsync = ctx.client("appsync")
    appsync.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)
        if status["status"] == "SUCCESS":
            return
        if status["status"] == "FAILED":
            raise AssertionError(f"schema creation failed: {status.get('details')}")
        time.sleep(2)
    raise AssertionError(f"schema creation timed out: {status}")


def _appsync_name(ctx: Any, prefix: str) -> str:
    return ctx.unique_name(prefix).replace("-", "_")


def _create_http_datasource(
    ctx: Any, api_id: str, endpoint: str, *, service_role_arn: str | None = None, authorization_config: dict | None = None
) -> str:
    appsync = ctx.client("appsync")
    ds_name = _appsync_name(ctx, "sim2real_ds_")
    http_config: dict[str, Any] = {"endpoint": endpoint}
    if authorization_config:
        http_config["authorizationConfig"] = authorization_config
    kwargs: dict[str, Any] = {"apiId": api_id, "name": ds_name, "type": "HTTP", "httpConfig": http_config}
    if service_role_arn:
        kwargs["serviceRoleArn"] = service_role_arn
    appsync.create_data_source(**kwargs)
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))
    return ds_name


def _create_unit_resolver(
    ctx: Any, api_id: str, type_name: str, field_name: str, ds_name: str, req_tpl: str, resp_tpl: str
) -> None:
    appsync = ctx.client("appsync")
    appsync.create_resolver(
        apiId=api_id,
        typeName=type_name,
        fieldName=field_name,
        dataSourceName=ds_name,
        requestMappingTemplate=req_tpl,
        responseMappingTemplate=resp_tpl,
    )
    ctx.on_cleanup(lambda: appsync.delete_resolver(apiId=api_id, typeName=type_name, fieldName=field_name))


def _graphql_request(ctx: Any, endpoint: str, headers: dict[str, str], query: str) -> dict[str, Any]:
    body = json.dumps({"query": query}).encode("utf-8")
    routed_url, route_headers = ctx.endpoint_route(endpoint)
    req = urllib.request.Request(routed_url, data=body, method="POST", headers=route_headers)
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=20, context=_ssl_context(ctx.http_verify)) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read())


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _poll_until(observe, predicate, *, timeout_s: float, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = observe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
