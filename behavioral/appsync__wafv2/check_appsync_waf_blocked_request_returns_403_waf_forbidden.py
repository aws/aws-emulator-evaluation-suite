"""appsync-waf-blocked-request-returns-403-waf-forbidden."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appsync-waf-blocked-request-returns-403-waf-forbidden"
GROUP = 'end-to-end'
SERVICES = ['appsync', 'wafv2']

BLOCK_HEADER = "x-fidelity-block"

SDL = """schema { query: Query }
type Query {
    ping: String
}
"""

JS_MARKER = """export function request(ctx) {
  return { payload: { marker: '%s' } };
}

export function response(ctx) {
  return ctx.result.marker;
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}




def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _alnum(ctx, prefix):
    """AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens allowed."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_text(ctx, url, headers, body, timeout_s=30):
    """POST -> (status, raw text), so a blocked body can be inspected before any json.loads."""
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=body, method="POST",
        headers={"Content-Type": "application/json", **headers, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, f"transport_error: {exc}"


def _graphql_api(ctx, svc, sdl, **api_kwargs):
    """Create a GraphQL API + an ACTIVE schema; return (api_id, uris, arn)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType=api_kwargs.pop("authenticationType", "API_KEY"),
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
        **api_kwargs,
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))
    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=120.0, interval_s=2.0,
        description="StartSchemaCreation to reach a terminal status",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), f"schema creation failed: {status!r}"
    uris = api.get("uris") or {}
    assert uris.get("GRAPHQL"), f"the API exposed no GRAPHQL endpoint URI: {uris!r}"
    return api_id, uris, api["arn"]


def _try_associate(waf, acl_arn, resource_arn):
    """True once the association succeeds; the AWS error code otherwise (never a bare bool
    False, so a poll timeout reports WHICH code kept it from settling)."""
    try:
        waf.associate_web_acl(WebACLArn=acl_arn, ResourceArn=resource_arn)
        return True
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "UnknownError")


def _delete_web_acl(ctx, name, acl_id):
    """Delete a WebACL, refetching its LockToken (a stale one is rejected) and tolerating the
    brief window in which it is still recorded as associated."""
    waf = ctx.client("wafv2")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            token = waf.get_web_acl(Name=name, Scope="REGIONAL", Id=acl_id)["LockToken"]
            waf.delete_web_acl(Name=name, Scope="REGIONAL", Id=acl_id, LockToken=token)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "WAFNonexistentItemException":
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"wafv2 WebACL {name} ({acl_id}) not deleted: {code}"
                ) from exc
            time.sleep(5.0)




@tags("axis:rejection", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A WAF Block rule refuses a GraphQL request with HTTP 403 before the resolver runs.

    The body has one WAFForbiddenException error, no `data` key; the same request minus the header
    still reaches the resolver.
    """
    svc = ctx.client("appsync")
    waf = ctx.client("wafv2")
    marker = ctx.unique_name("ping-")

    api_id, uris, api_arn = _graphql_api(ctx, svc, SDL)
    graphql_uri = uris["GRAPHQL"]

    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))
    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="ping",
        kind="UNIT", dataSourceName=ds["name"], runtime=APPSYNC_JS, code=JS_MARKER % marker,
    )
    ctx.on_cleanup(
        lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="ping")
    )
    api_key = svc.create_api_key(
        apiId=api_id, description="sim2real-behav appsync waf key"
    )["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=api_key))

    body = json.dumps({"query": "query { ping }"}).encode()

    # Before WAF exists, the endpoint answers -- so a 403 later cannot be a broken API.
    pre_status, pre_body = _poll_until(
        lambda: _post_text(ctx, graphql_uri, {"x-api-key": api_key}, body),
        lambda res: res[0] == 200,
        timeout_s=120.0, interval_s=3.0,
        description="the unprotected GraphQL endpoint to answer",
    )
    assert json.loads(pre_body)["data"]["ping"] == marker, (
        f"the resolver did not answer before WAF was attached: {pre_status!r} {pre_body!r}"
    )

    acl_name = _alnum(ctx, "sim2realbehavappsyncacl")
    acl = waf.create_web_acl(
        Name=acl_name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        Rules=[{
            "Name": "blockmarkedheader",
            "Priority": 0,
            "Statement": {"ByteMatchStatement": {
                "SearchString": b"yes",
                "FieldToMatch": {"SingleHeader": {"Name": BLOCK_HEADER}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "EXACTLY",
            }},
            "Action": {"Block": {}},
            "VisibilityConfig": {"SampledRequestsEnabled": False,
                                 "CloudWatchMetricsEnabled": False,
                                 "MetricName": "blockmarkedheader"},
        }],
        VisibilityConfig={"SampledRequestsEnabled": False,
                          "CloudWatchMetricsEnabled": False,
                          "MetricName": acl_name[:100]},
        Tags=[{"Key": "sim2real", "Value": CHECK},
              {"Key": "sim2real:managed", "Value": "true"}],
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_web_acl(ctx, acl_name, acl["Id"]))

    # AssociateWebACL raises WAFUnavailableEntityException against an AppSync API created seconds
    # earlier -- WAF's view of the resource is eventually consistent.
    associated = _poll_until(
        lambda: _try_associate(waf, acl["ARN"], api_arn),
        lambda outcome: outcome is True,
        timeout_s=180.0, interval_s=5.0,
        description="AssociateWebACL to stop reporting the AppSync API as unavailable",
    )
    assert associated is True, f"the WebACL could not be associated: {associated!r}"
    ctx.on_cleanup(lambda: waf.disassociate_web_acl(ResourceArn=api_arn))

    attached = _poll_until(
        lambda: (waf.get_web_acl_for_resource(ResourceArn=api_arn).get("WebACL") or {}),
        lambda w: w.get("ARN") == acl["ARN"],
        timeout_s=120.0, interval_s=3.0,
        description="the WebACL to be reported as associated with the AppSync API",
    )
    assert attached["ARN"] == acl["ARN"], (
        f"a different WebACL is attached to the API: {attached!r}"
    )

    # Propagation to the AppSync edge takes time; poll until the request is actually blocked.
    blocked_status, blocked_body = _poll_until(
        lambda: _post_text(
            ctx, graphql_uri, {"x-api-key": api_key, BLOCK_HEADER: "yes"}, body
        ),
        lambda res: res[0] == 403,
        timeout_s=180.0, interval_s=5.0,
        description="the marked request to be blocked by the associated WebACL",
    )
    assert blocked_status == 403, (
        f"WAF did not block the marked request, got {blocked_status!r}: {blocked_body[:300]!r}"
    )
    blocked = json.loads(blocked_body)
    assert "data" not in blocked, (
        f"a WAF-blocked request still returned a GraphQL data envelope, so it reached the "
        f"resolver: {blocked_body[:300]!r}"
    )
    blocked_errors = blocked.get("errors") or []
    assert len(blocked_errors) == 1, (
        f"expected exactly one error on the edge refusal, got {blocked_errors!r}"
    )
    assert blocked_errors[0].get("errorType") == "WAFForbiddenException", (
        f"the 403 was not attributed to WAF; got errorType "
        f"{blocked_errors[0].get('errorType')!r} in {blocked_body[:300]!r}"
    )
    assert blocked_errors[0].get("message") == "403 Forbidden", (
        f"the WAF refusal carries the wrong message: {blocked_errors[0].get('message')!r} in "
        f"{blocked_body[:300]!r}"
    )
    assert marker not in blocked_body, (
        f"the blocked response leaked the resolver's marker, so the resolver ran: "
        f"{blocked_body[:300]!r}"
    )

    # ---- positive control: identical request, header removed, same WebACL still attached ----
    allowed_status, allowed_body = _post_text(ctx, graphql_uri, {"x-api-key": api_key}, body)
    assert allowed_status == 200, (
        f"the control request was blocked too, so the WebACL is blocking everything: "
        f"{allowed_status!r} {allowed_body[:300]!r}"
    )
    allowed = json.loads(allowed_body)
    assert allowed.get("errors") is None, f"the control request errored: {allowed!r}"
    assert allowed["data"]["ping"] == marker, (
        f"the control request did not reach the resolver: {allowed!r}"
    )

    still_attached = waf.get_web_acl_for_resource(ResourceArn=api_arn).get("WebACL") or {}
    assert still_attached.get("ARN") == acl["ARN"], (
        f"the WebACL detached itself between the two legs, so the control proves nothing: "
        f"{still_attached!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
