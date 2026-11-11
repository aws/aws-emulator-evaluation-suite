"""e2e-ipset-block-then-update-allows-traffic."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-ipset-block-then-update-allows-traffic"
GROUP = "e2e"
SERVICES = ["wafv2"]


#: Documentation addresses (RFC 5737) the check sends as the client; never a real runner's.
LISTED_IP, UNLISTED_IP = "198.51.100.7", "203.0.113.9"
CLIENT_HEADER = "X-Forwarded-For"


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """End to end: an IPSet holding a client address, matched through a forwarded-IP header by a
    Block rule in an associated WebACL, blocks requests claiming that address and no others;
    after UpdateIPSet removes it, the same requests pass. Then everything is torn down.
    """
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    api = _create_mock_rest_api(ctx)

    resource_tags = [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]

    ip_set_name = ctx.unique_name("sim2real-behav-e2e-ipset-")
    ip_set_create = wafv2.create_ip_set(
        Name=ip_set_name,
        Scope=scope,
        IPAddressVersion="IPV4",
        Addresses=[f"{LISTED_IP}/32"],
        Tags=resource_tags,
    )
    ip_set_id = ip_set_create["Summary"]["Id"]
    ip_set_arn = ip_set_create["Summary"]["ARN"]

    web_acl_name = ctx.unique_name("sim2real-behav-e2e-webacl-")
    metric_name = web_acl_name.replace("-", "")
    # The IPSet ARN just created above can take a short while to become resolvable by
    # other WAFv2 operations that reference it (WAFUnavailableEntityException: "AWS
    # WAF couldn't retrieve the resource") -- poll through that propagation window.
    web_acl_create = _retry_unavailable(
        lambda: wafv2.create_web_acl(
            Name=web_acl_name,
            Scope=scope,
            DefaultAction={"Allow": {}},
            Rules=[
                {
                    "Name": "block-listed-client",
                    "Priority": 0,
                    "Action": {"Block": {}},
                    "Statement": {
                        "IPSetReferenceStatement": {
                            "ARN": ip_set_arn,
                            "IPSetForwardedIPConfig": {
                                "HeaderName": CLIENT_HEADER,
                                "FallbackBehavior": "NO_MATCH",
                                "Position": "FIRST",
                            },
                        }
                    },
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": f"{metric_name}rule",
                    },
                }
            ],
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": metric_name,
            },
            Tags=resource_tags,
        )
    )
    web_acl_id = web_acl_create["Summary"]["Id"]
    web_acl_arn = web_acl_create["Summary"]["ARN"]

    def _teardown() -> None:
        # Safety net for an early failure: the main body below already disassociates
        # and deletes both resources on the happy path, so only WAFNonexistentItemException
        # (nothing left to remove) is tolerated; any other error raises.
        try:
            wafv2.disassociate_web_acl(ResourceArn=api["resource_arn"])
        except ClientError as err:
            if err.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise
        try:
            current = wafv2.get_web_acl(Name=web_acl_name, Scope=scope, Id=web_acl_id)
            wafv2.delete_web_acl(Name=web_acl_name, Scope=scope, Id=web_acl_id, LockToken=current["LockToken"])
        except ClientError as err:
            if err.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise
        try:
            current = wafv2.get_ip_set(Name=ip_set_name, Scope=scope, Id=ip_set_id)
            wafv2.delete_ip_set(Name=ip_set_name, Scope=scope, Id=ip_set_id, LockToken=current["LockToken"])
        except ClientError as err:
            if err.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    ctx.on_cleanup(_teardown)

    listed = {CLIENT_HEADER: LISTED_IP}
    seen: list[int | None] = []
    try:
        baseline = _poll_until(
            lambda: seen.append(_http_status(api["invoke_url"], listed, ctx.http_verify)) or seen[-1],
            lambda s: s == 200, timeout_s=60.0,
        )
    except AssertionError as exc:
        if all(s is None for s in seen):
            raise AssertionError(
                f"DATAPLANE_UNIMPLEMENTED: nothing answered at the deployed stage {api['invoke_url']} "
                f"within 60s, so WAF evaluation of its traffic could not be observed at all"
            ) from exc
        raise
    assert baseline == 200, f"expected the unassociated API to answer 200 before WAF is involved, got {baseline}"

    _retry_unavailable(lambda: wafv2.associate_web_acl(WebACLArn=web_acl_arn, ResourceArn=api["resource_arn"]))

    blocked = _poll_until(
        lambda: _http_status(api["invoke_url"], listed, ctx.http_verify), lambda s: s == 403, timeout_s=120.0
    )
    assert blocked == 403, f"expected {LISTED_IP} to be blocked once associated, got {blocked}"
    control = _http_status(api["invoke_url"], {CLIENT_HEADER: UNLISTED_IP}, ctx.http_verify)
    assert control == 200, (
        f"expected {UNLISTED_IP}, absent from the IPSet, to pass while {LISTED_IP} is blocked, "
        f"got {control}"
    )

    current = wafv2.get_ip_set(Name=ip_set_name, Scope=scope, Id=ip_set_id)
    wafv2.update_ip_set(
        Name=ip_set_name,
        Scope=scope,
        Id=ip_set_id,
        Addresses=[],
        LockToken=current["LockToken"],
    )

    unblocked = _poll_until(
        lambda: _http_status(api["invoke_url"], listed, ctx.http_verify), lambda s: s == 200, timeout_s=120.0
    )
    assert unblocked == 200, (
        f"expected {LISTED_IP} to no longer be blocked after removing it from the "
        f"IPSet, got {unblocked}"
    )

    # Put the address back so the association is what blocks it, then disassociate: the listed
    # client passing again proves the association is gone at the consumer, not just unlisted.
    current = wafv2.get_ip_set(Name=ip_set_name, Scope=scope, Id=ip_set_id)
    wafv2.update_ip_set(
        Name=ip_set_name, Scope=scope, Id=ip_set_id, Addresses=[f"{LISTED_IP}/32"],
        LockToken=current["LockToken"],
    )
    reblocked = _poll_until(
        lambda: _http_status(api["invoke_url"], listed, ctx.http_verify), lambda s: s == 403, timeout_s=120.0
    )
    assert reblocked == 403, f"expected {LISTED_IP} to be blocked again once re-listed, got {reblocked}"

    wafv2.disassociate_web_acl(ResourceArn=api["resource_arn"])
    association = wafv2.get_web_acl_for_resource(ResourceArn=api["resource_arn"])
    assert not association.get("WebACL"), (
        f"expected no WebACL associated with the stage after DisassociateWebACL, got {association.get('WebACL')!r}"
    )
    released = _poll_until(
        lambda: _http_status(api["invoke_url"], listed, ctx.http_verify), lambda s: s == 200, timeout_s=120.0
    )
    assert released == 200, f"expected {LISTED_IP} to pass once the WebACL is disassociated, got {released}"

    # Deletes prove gone and unusable: the WebACL and IPSet this check created must
    # disappear behind an independent read and the listing, and refuse a mutation.
    web_acl_current = wafv2.get_web_acl(Name=web_acl_name, Scope=scope, Id=web_acl_id)
    assert web_acl_id in _listed_ids(wafv2.list_web_acls, "WebACLs", scope), "the live WebACL must be listed"
    wafv2.delete_web_acl(
        Name=web_acl_name, Scope=scope, Id=web_acl_id, LockToken=web_acl_current["LockToken"]
    )
    _assert_nonexistent(
        _error(lambda: wafv2.get_web_acl(Name=web_acl_name, Scope=scope, Id=web_acl_id)),
        "GetWebACL on the deleted WebACL",
    )
    assert web_acl_id not in _listed_ids(wafv2.list_web_acls, "WebACLs", scope), "the deleted WebACL is still listed"
    _assert_nonexistent(
        _error(lambda: wafv2.update_web_acl(
            Name=web_acl_name, Scope=scope, Id=web_acl_id, DefaultAction={"Allow": {}}, Rules=[],
            VisibilityConfig={"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                              "MetricName": metric_name},
            LockToken=web_acl_current["LockToken"],
        )),
        "UpdateWebACL on the deleted WebACL",
    )

    ip_set_current = wafv2.get_ip_set(Name=ip_set_name, Scope=scope, Id=ip_set_id)
    assert ip_set_id in _listed_ids(wafv2.list_ip_sets, "IPSets", scope), "the live IPSet must be listed"
    wafv2.delete_ip_set(
        Name=ip_set_name, Scope=scope, Id=ip_set_id, LockToken=ip_set_current["LockToken"]
    )
    _assert_nonexistent(
        _error(lambda: wafv2.get_ip_set(Name=ip_set_name, Scope=scope, Id=ip_set_id)),
        "GetIPSet on the deleted IPSet",
    )
    assert ip_set_id not in _listed_ids(wafv2.list_ip_sets, "IPSets", scope), "the deleted IPSet is still listed"
    _assert_nonexistent(
        _error(lambda: wafv2.update_ip_set(
            Name=ip_set_name, Scope=scope, Id=ip_set_id, Addresses=[],
            LockToken=ip_set_current["LockToken"],
        )),
        "UpdateIPSet on the deleted IPSet",
    )


def _error(fn) -> tuple[str, int, str]:
    """Return (code, HTTP status, message) of the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["ResponseMetadata"]["HTTPStatusCode"],
            err.response["Error"].get("Message", ""),
        )
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _assert_nonexistent(err: tuple[str, int, str], what: str) -> None:
    """WAFNonexistentItemException + 400 + a non-empty message (AWS's wording does not name the id)."""
    code, status, message = err
    assert (code, status) == ("WAFNonexistentItemException", 400), (
        f"{what}: expected WAFNonexistentItemException/400, got {code}/{status}"
    )
    assert message, f"{what}: expected a non-empty message, got {message!r}"


def _listed_ids(lister, key: str, scope: str) -> set[str]:
    """Every id the WAFv2 *lister* returns in *scope*, following NextMarker."""
    ids, kwargs = set(), {"Scope": scope, "Limit": 100}
    while True:
        page = lister(**kwargs)
        ids.update(item["Id"] for item in page[key])
        marker = page.get("NextMarker")
        if not marker or not page[key]:
            return ids
        kwargs["NextMarker"] = marker


def _retry_unavailable(fn, *, timeout_s: float = 180.0, interval_s: float = 10.0):
    """A just-created WAFv2 resource can be transiently unresolvable to a dependent
    WAFv2 call (WAFUnavailableEntityException: "AWS WAF couldn't retrieve the
    resource") -- eventual-consistency propagation, not a real rejection. Poll
    through it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "WAFUnavailableEntityException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http_status(url: str, headers: dict[str, str], verify, timeout: float = 10.0) -> int | None:
    """The HTTP status the stage answers, or None when nothing answered. A TLS failure is not
    'nothing answered': it raises, naming the handshake error."""
    req = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_ssl_context(verify)))
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as err:
        return err.code
    except (urllib.error.URLError, OSError) as err:
        reason = getattr(err, "reason", err)
        if isinstance(reason, ssl.SSLError) or isinstance(err, ssl.SSLError):
            raise AssertionError(f"TLS handshake with {url} failed: {reason}") from err
        return None


def _poll_until(probe, predicate, timeout_s: float = 90.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _create_mock_rest_api(ctx) -> dict:
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-api-")
    api = apigw.create_rest_api(name=name, endpointConfiguration={"types": ["REGIONAL"]})
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(
        r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": ""},
    )
    stage_name = "test"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    invoke_url = f"{ctx.rest_api_url(api_id, stage_name)}/"
    resource_arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}/stages/{stage_name}"
    return {"api_id": api_id, "invoke_url": invoke_url, "resource_arn": resource_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
