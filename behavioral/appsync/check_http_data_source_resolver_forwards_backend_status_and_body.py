"""http-data-source-resolver-forwards-backend-status-and-body."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any

from behavioral_harness import tags

CHECK = "http-data-source-resolver-forwards-backend-status-and-body"
GROUP = "data-source"
SERVICES = ["appsync"]

SCHEMA = """
type BackendResponse {
    statusCode: Int
    body: String
}
type Query {
    identityCall: BackendResponse
    bogusActionCall: BackendResponse
}
schema {
    query: Query
}
"""

RESPONSE_TPL = """
{
  "statusCode": $ctx.result.statusCode,
  "body": $util.toJson($ctx.result.body)
}
"""

IDENTITY_REQUEST_TPL = """
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

BOGUS_ACTION_REQUEST_TPL = """
{
  "version": "2018-05-29",
  "method": "GET",
  "resourcePath": "/",
  "params": {
    "query": {
      "Action": "BogusAction",
      "Version": "2011-06-15"
    }
  }
}
"""

QUERY_IDENTITY = "{ identityCall { statusCode body } }"
QUERY_BOGUS = "{ bogusActionCall { statusCode body } }"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx: Any) -> None:
    """An HTTP data source resolver returns the backend's own status code and body verbatim,
    varying per request rather than a value AppSync itself produced.
    """
    api = _create_graphql_api(ctx)
    api_key = _create_api_key(ctx, api["apiId"])
    _deploy_schema(ctx, api["apiId"], SCHEMA)
    ds_name = _create_http_datasource(ctx, api["apiId"], "https://sts.us-west-2.amazonaws.com")
    _create_unit_resolver(ctx, api["apiId"], "Query", "identityCall", ds_name, IDENTITY_REQUEST_TPL, RESPONSE_TPL)
    _create_unit_resolver(ctx, api["apiId"], "Query", "bogusActionCall", ds_name, BOGUS_ACTION_REQUEST_TPL, RESPONSE_TPL)

    headers = {"x-api-key": api_key}

    identity_resp = _poll_until(
        lambda: _graphql_request(ctx, api["endpoint"], headers, QUERY_IDENTITY),
        lambda r: not r.get("errors") and (r.get("data") or {}).get("identityCall"),
        timeout_s=45.0,
    )
    assert identity_resp is not None and not identity_resp.get("errors"), (
        f"identityCall query failed: {identity_resp}"
    )
    identity = identity_resp["data"]["identityCall"]
    assert identity["statusCode"] == 403, f"expected statusCode 403, got {identity['statusCode']!r}"
    identity_error = _parse_sts_error(identity["body"])
    assert identity_error == ("Sender", "MissingAuthenticationToken", "Request is missing Authentication Token"), (
        f"unexpected identity call error {identity_error!r}"
    )

    bogus_resp = _graphql_request(ctx, api["endpoint"], headers, QUERY_BOGUS)
    assert bogus_resp is not None and not bogus_resp.get("errors"), f"bogusActionCall query failed: {bogus_resp}"
    bogus = bogus_resp["data"]["bogusActionCall"]
    assert bogus["statusCode"] == 400, f"expected statusCode 400, got {bogus['statusCode']!r}"
    bogus_error = _parse_sts_error(bogus["body"])
    assert bogus_error == ("Sender", "InvalidAction", "Could not find operation BogusAction for version 2011-06-15"), (
        f"unexpected bogus action error {bogus_error!r}"
    )


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


def _create_http_datasource(ctx: Any, api_id: str, endpoint: str) -> str:
    appsync = ctx.client("appsync")
    ds_name = _appsync_name(ctx, "sim2real_ds_")
    appsync.create_data_source(
        apiId=api_id,
        name=ds_name,
        type="HTTP",
        httpConfig={"endpoint": endpoint},
    )
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
