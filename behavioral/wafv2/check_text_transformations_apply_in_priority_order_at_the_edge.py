"""text-transformations-apply-in-priority-order-at-the-edge."""
from __future__ import annotations

import datetime
import random
import string
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "text-transformations-apply-in-priority-order-at-the-edge"
GROUP = "rule-evaluation"
SERVICES = ["wafv2"]

# DeleteRestApi is throttled to ~1 call/30s per account, so `_delete_api` raises naming the API
# it could not delete.

# Carried in a failure detail when the endpoint serves no data-plane response, so a missing data
# plane reads as a failed check rather than as a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# ===== helpers =====
# Every budget below is a ceiling on a bounded poll to an OBSERVABLE condition, never a sleep
# and never itself asserted.

SCOPE = "REGIONAL"
ERR_NONEXISTENT = "WAFNonexistentItemException"

_ASSOCIATE_BUDGET_S = 420.0    # Observed on AWS: AssociateWebACL refuses a freshly
# created API Gateway stage with WAFUnavailableEntityException and settled at 41.6s.
_PROPAGATION_BUDGET_S = 360.0  # Observed on AWS: a rule change reached the edge in 20-30s.
_API_DELETE_BUDGET_S = 420.0   # Observed on AWS: DeleteRestApi is throttled to roughly
# one call per 30s per ACCOUNT, so an unguarded teardown delete leaks the REST API silently.

_TRANSIENT = frozenset({"ThrottlingException", "WAFInternalErrorException",
                        "WAFOptimisticLockException", "WAFUnavailableEntityException"})


def _tok(n=10):
    """Lowercase alphanumeric token (stage names and WAF metric names reject hyphens)."""
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _vis(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}


def _http(method, url, body=None, headers=None, timeout_s=25):
    """(status, lowercased response headers, body text). status is None on a transport error."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 - fixed scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return (None, {}, f"transport_error: {exc}")


def _poll(fn, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Re-run fn until predicate holds. RAISES on expiry -- never returns its last value and
    never Skips: a target that never reaches the expected state is the finding."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = fn()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)


def _retry_transient(fn, *, timeout_s=240.0, interval_s=10.0):
    """Bounded retry over WAF's eventually-consistent control-plane codes ONLY; every other
    ClientError is re-raised so a real refusal can never be disguised as a timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") not in _TRANSIENT:
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _root_id(ag, api_id):
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise AssertionError("the REST API exposed no root ('/') resource")


def _delete_api(ag, api_id):
    deadline = time.monotonic() + _API_DELETE_BUDGET_S
    while True:
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise RuntimeError(
                    f"apigateway RestApi {api_id} not deleted: {code}"
                ) from exc
            time.sleep(15.0)


def _create_api(ctx, ag):
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-waf-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["id"]
    ctx.on_cleanup(lambda: _delete_api(ag, api_id))
    return api_id


def _mock(ag, api_id, parent_id, path_part, template, method="GET"):
    """A fully wired MOCK method under parent_id: 200 request template + 200 response template."""
    rid = ag.create_resource(restApiId=api_id, parentId=parent_id, pathPart=path_part)["id"]
    ag.put_method(restApiId=api_id, resourceId=rid, httpMethod=method, authorizationType="NONE")
    ag.put_integration(restApiId=api_id, resourceId=rid, httpMethod=method, type="MOCK",
                       requestTemplates={"application/json": '{"statusCode": 200}'})
    ag.put_method_response(restApiId=api_id, resourceId=rid, httpMethod=method, statusCode="200")
    ag.put_integration_response(restApiId=api_id, resourceId=rid, httpMethod=method,
                                statusCode="200", selectionPattern="",
                                responseTemplates={"application/json": template})
    return rid


def _deploy(ctx, ag, api_id):
    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    stage = f"s{_tok()}"
    ag.create_stage(restApiId=api_id, stageName=stage, deploymentId=deployment_id)
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=api_id, stageName=stage))
    return stage


def _stage_arn(ctx, api_id, stage):
    """The ARN AssociateWebACL takes for a REST API stage. Region from ctx, account not needed."""
    return f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}/stages/{stage}"


def _base_url(ctx, api_id, stage):
    """Invoke URL for a deployed stage, in the form the target serves it."""
    return ctx.rest_api_url(api_id, stage)


def _delete_web_acl(w, name, acl_id):
    """Delete a WebACL, refetching its LockToken (a stale one is rejected) and tolerating the
    window in which it is still recorded as associated with a resource."""
    deadline = time.monotonic() + 240.0
    while True:
        try:
            token = w.get_web_acl(Name=name, Scope=SCOPE, Id=acl_id)["LockToken"]
            w.delete_web_acl(Name=name, Scope=SCOPE, Id=acl_id, LockToken=token)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == ERR_NONEXISTENT:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"wafv2 WebACL {name} ({acl_id}) not deleted: {code}"
                ) from exc
            time.sleep(5.0)


def _delete_locked(getter, deleter, name, id_, label):
    """Delete any lock-tokened WAFv2 entity, refetching its LockToken. Reports a leak loudly
    rather than silently passing, and treats an already-absent entity as done."""
    deadline = time.monotonic() + 240.0
    while True:
        try:
            token = getter(Name=name, Scope=SCOPE, Id=id_)["LockToken"]
            deleter(Name=name, Scope=SCOPE, Id=id_, LockToken=token)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == ERR_NONEXISTENT:
                return
            if time.monotonic() >= deadline:
                print(f"wafv2 {label} {name} ({id_}) not deleted: {code}")
                return
            time.sleep(5.0)


def _create_web_acl(ctx, w, rules, default_action=None, **kwargs):
    name = "sim2realbehavwafacl" + _tok(10)
    summary = _retry_transient(lambda: w.create_web_acl(
        Name=name, Scope=SCOPE, DefaultAction=default_action or {"Allow": {}}, Rules=rules,
        VisibilityConfig=_vis(name[:100]),
        Tags=[{"Key": "sim2real", "Value": CHECK},
              {"Key": "sim2real:managed", "Value": "true"}],
        **kwargs,
    ))["Summary"]
    ctx.on_cleanup(lambda: _delete_web_acl(w, name, summary["Id"]))
    return name, summary


def _replace_rules(w, name, acl_id, rules, default_action=None, **kwargs):
    """UpdateWebACL with a freshly fetched LockToken; returns the response."""
    def _once():
        token = w.get_web_acl(Name=name, Scope=SCOPE, Id=acl_id)["LockToken"]
        return w.update_web_acl(Name=name, Scope=SCOPE, Id=acl_id, LockToken=token,
                                DefaultAction=default_action or {"Allow": {}}, Rules=rules,
                                VisibilityConfig=_vis(name[:100]), **kwargs)

    return _retry_transient(_once)


def _associate(ctx, w, acl_arn, resource_arn):
    """Associate, polling out WAFUnavailableEntityException. Observed on AWS: WAF's view
    of a freshly created API Gateway stage is eventually consistent and settled at 41.6s, so this
    is a bounded poll on the OBSERVABLE outcome and never a bare sleep."""
    def _attempt():
        try:
            w.associate_web_acl(WebACLArn=acl_arn, ResourceArn=resource_arn)
            return True
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code", "UnknownError")

    outcome = _poll(_attempt, lambda o: o is True, timeout_s=_ASSOCIATE_BUDGET_S, interval_s=2.0,
                    description="AssociateWebACL to stop reporting the stage as unavailable")
    assert outcome is True, f"the WebACL could not be associated with the stage: {outcome!r}"
    ctx.on_cleanup(lambda: w.disassociate_web_acl(ResourceArn=resource_arn))


def _wait_http(url, predicate, *, timeout_s, description, method="GET", body=None, headers=None):
    """Poll the edge until predicate(status, headers, text). A never-answering endpoint is a
    data-plane FAIL, never a Skip: nothing answering at an address the target chose and claims to
    serve IS the data-plane failure this check exists to find."""
    seen = []

    def _once():
        res = _http(method, url, body=body, headers=headers)
        seen.append(res[0])
        return res

    try:
        return _poll(_once, lambda r: predicate(*r), timeout_s=timeout_s, interval_s=2.0,
                     description=description)
    except AssertionError as exc:
        if all(s is None for s in seen):
            raise AssertionError(
                f"{DATAPLANE_MARKER}: nothing answered at {url} within {timeout_s}s, so WAF rule "
                f"evaluation could not be observed at all"
            ) from exc
        raise


def _stable_http(url, want, *, timeout_s, description, consecutive=4, headers=None,
                 method="GET", body=None, interval_s=2.0):
    """Poll until the edge answers `want` on `consecutive` SUCCESSIVE requests; return the last.

    On real AWS a WAF rule change reaches API Gateway's edge
    unevenly -- a 403 was observed and a request seconds later still returned 200 -- so a single
    observation of the expected state is not evidence that the state has settled. Requiring a run
    of identical answers is what makes a LATER single-request assertion trustworthy rather than a
    race against propagation.
    """
    seen = []
    state = {"run": 0, "last": None}

    def _once():
        res = _http(method, url, body=body, headers=headers)
        seen.append(res[0])
        state["run"] = state["run"] + 1 if res[0] == want else 0
        state["last"] = res
        return state["run"]

    try:
        _poll(_once, lambda n: n >= consecutive, timeout_s=timeout_s, interval_s=interval_s,
              description=description)
    except AssertionError as exc:
        if all(s is None for s in seen):
            raise AssertionError(
                f"{DATAPLANE_MARKER}: nothing answered at {url} within {timeout_s}s, so WAF rule "
                f"evaluation could not be observed at all"
            ) from exc
        raise AssertionError(
            f"{description} not observed on {consecutive} successive requests within "
            f"{timeout_s}s; statuses were {seen[-12:]!r}"
        ) from exc
    return state["last"]


def _byte_match(header, value, *, transforms=None, constraint="EXACTLY"):
    """A ByteMatchStatement on one request header. A header is used rather than the URI path
    because WAF inspects the STAGE-QUALIFIED path, and because no
    intermediary rewrites a header VALUE."""
    return {"ByteMatchStatement": {
        "SearchString": value.encode() if isinstance(value, str) else value,
        "FieldToMatch": {"SingleHeader": {"Name": header}},
        "TextTransformations": transforms or [{"Priority": 0, "Type": "NONE"}],
        "PositionalConstraint": constraint}}


def _sample_for(w, acl_arn, marker, *, rule_metric, timeout_s=300.0):
    """Poll GetSampledRequests until a sample attributed to `rule_metric` carries `marker` in one
    of its request headers, and return it.

    The TimeWindow comes from the LIVE UTC clock. Sampling is
    asynchronous, so this is a bounded poll that RAISES on expiry -- it never returns an empty
    list, which a hardcoded ``[]`` would satisfy.
    """
    def _once():
        now = datetime.datetime.now(datetime.timezone.utc)
        resp = w.get_sampled_requests(
            WebAclArn=acl_arn, RuleMetricName=rule_metric, Scope=SCOPE,
            TimeWindow={"StartTime": now - datetime.timedelta(minutes=15),
                        "EndTime": now + datetime.timedelta(minutes=1)},
            MaxItems=500,
        )
        for s in resp.get("SampledRequests", []):
            for h in s.get("Request", {}).get("Headers", []):
                if marker in (h.get("Value") or ""):
                    return s
        return None

    return _poll(_once, lambda s: s is not None, timeout_s=timeout_s, interval_s=2.0,
                 description=(f"a sampled request for rule metric {rule_metric!r} carrying the "
                              f"marker {marker!r}"))
# ===== end helpers =====

# A percent-encoded value whose match outcome DEPENDS on transformation order:
#   URL_DECODE then LOWERCASE:  "%41DMIN" -> "ADMIN"   -> "admin"  == the search string
#   LOWERCASE then URL_DECODE:  "%41DMIN" -> "%41dmin" -> "Admin"  != the search string
_ORDER_SENSITIVE = "%41DMIN"
# ...and one whose outcome does NOT depend on the order, used as the per-order positive control:
#   URL_DECODE then LOWERCASE:  "%61DMIN" -> "aDMIN"   -> "admin"
#   LOWERCASE then URL_DECODE:  "%61DMIN" -> "%61dmin" -> "admin"
_ORDER_INSENSITIVE = "%61DMIN"
_SEARCH = b"admin"


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Text transformations are applied in ascending Priority order: swapping only the two
    priorities flips the verdict for a value that matches in one order,
    while a control matches in both.
    """
    ag = ctx.client("apigateway")
    w = ctx.client("wafv2")

    origin_marker = "origin" + _tok(8)

    api_id = _create_api(ctx, ag)
    _mock(ag, api_id, _root_id(ag, api_id), "transform", '{"origin":"%s"}' % origin_marker)
    stage = _deploy(ctx, ag, api_id)
    url = _base_url(ctx, api_id, stage) + "/transform"
    stage_arn = _stage_arn(ctx, api_id, stage)

    pre = _wait_http(url, lambda s, h, t: s == 200, timeout_s=180.0,
                     description=f"GET {url} to serve its MOCK integration")
    assert origin_marker in pre[2], (
        f"the origin was not answering before WAF was attached, so nothing below proves "
        f"anything: status={pre[0]!r} body={pre[2][:200]!r}"
    )

    def _rule(*types):
        return {"Name": "ttrule", "Priority": 0,
                "Statement": {"ByteMatchStatement": {
                    "SearchString": _SEARCH,
                    "FieldToMatch": {"SingleHeader": {"Name": "x-waf-tt"}},
                    "TextTransformations": [{"Priority": i, "Type": t}
                                            for i, t in enumerate(types)],
                    "PositionalConstraint": "EXACTLY"}},
                "Action": {"Block": {}}, "VisibilityConfig": _vis("ttrule")}

    decode_first = _rule("URL_DECODE", "LOWERCASE")
    lower_first = _rule("LOWERCASE", "URL_DECODE")

    acl_name, acl = _create_web_acl(ctx, w, [decode_first])
    acl_arn = acl["ARN"]
    stored_tt = (w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"])["WebACL"]["Rules"][0]
                 ["Statement"]["ByteMatchStatement"]["TextTransformations"])
    assert stored_tt == [{"Priority": 0, "Type": "URL_DECODE"},
                         {"Priority": 1, "Type": "LOWERCASE"}], (
        f"WAF did not store the transformation list in the order it was given, so every leg "
        f"below would compare the wrong thing: {stored_tt!r}"
    )
    _associate(ctx, w, acl_arn, stage_arn)

    # ---- leg 1: URL_DECODE then LOWERCASE, order-INSENSITIVE value. Positive control for
    # this order: it proves the statement and both transformations work at all.
    baseline = _stable_http(
        url, 403, timeout_s=_PROPAGATION_BUDGET_S, headers={"x-waf-tt": _ORDER_INSENSITIVE},
        description=f"{_ORDER_INSENSITIVE!r} to be blocked under URL_DECODE-then-LOWERCASE")
    assert baseline[0] == 403, (
        f"{_ORDER_INSENSITIVE!r} -- which becomes the search string {_SEARCH!r} under EITHER "
        f"transformation order -- was not blocked, so the transformations are not applied to the "
        f"header value at all and no later leg proves anything: status={baseline[0]!r} "
        f"body={baseline[2][:200]!r}"
    )

    # ---- leg 2: the order-SENSITIVE value, same order -> matches -> BLOCK.
    sensitive = _stable_http(
        url, 403, timeout_s=_PROPAGATION_BUDGET_S, headers={"x-waf-tt": _ORDER_SENSITIVE},
        description=f"{_ORDER_SENSITIVE!r} to be blocked under URL_DECODE-then-LOWERCASE")
    assert sensitive[0] == 403, (
        f"{_ORDER_SENSITIVE!r} was not blocked under URL_DECODE(0)+LOWERCASE(1), so the "
        f"transformations were not applied to the header value at all: status={sensitive[0]!r} "
        f"body={sensitive[2][:200]!r}"
    )
    assert origin_marker not in sensitive[2], (
        f"the blocked request still reached the origin: {sensitive[2][:200]!r}"
    )
    sample = _sample_for(w, acl_arn, _ORDER_SENSITIVE, rule_metric="ttrule")
    assert sample.get("Action") == "BLOCK", (
        f"the transformed match was not attributed as a BLOCK to the rule: "
        f"Action={sample.get('Action')!r}"
    )

    # ---- leg 3: a value that matches under NEITHER order -> served. Guards "blocks all".
    negative = _wait_http(
        url, lambda s, h, t: s == 200, timeout_s=120.0,
        headers={"x-waf-tt": "notadmin" + _tok(6)},
        description="a value that no transformation chain turns into the search string to be "
                    "served")
    assert origin_marker in negative[2], (
        f"a header value that cannot become {_SEARCH!r} under either transformation order was "
        f"blocked: status={negative[0]!r} body={negative[2][:200]!r}"
    )

    # ---- leg 4: break exactly one thing -- swap the two transformation priorities.
    _replace_rules(w, acl_name, acl["Id"], [lower_first])
    stored_tt2 = (w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"])["WebACL"]["Rules"][0]
                  ["Statement"]["ByteMatchStatement"]["TextTransformations"])
    assert stored_tt2 == [{"Priority": 0, "Type": "LOWERCASE"},
                          {"Priority": 1, "Type": "URL_DECODE"}], (
        f"the transformation-order swap was not stored, so leg 4 would re-test leg 2: "
        f"{stored_tt2!r}"
    )

    # 4a: positive control for the NEW order, in the same instant. The order-insensitive value
    # must still be blocked, so a 200 in 4b cannot be "the rule broke".
    ctl = _stable_http(
        url, 403, timeout_s=_PROPAGATION_BUDGET_S, headers={"x-waf-tt": _ORDER_INSENSITIVE},
        description=f"{_ORDER_INSENSITIVE!r} to still be blocked under "
                    f"LOWERCASE-then-URL_DECODE")
    assert ctl[0] == 403, (
        f"{_ORDER_INSENSITIVE!r} stopped matching after the order swap, so the rule itself is "
        f"broken and leg 4b would prove nothing: status={ctl[0]!r} body={ctl[2][:200]!r}"
    )

    # 4b: THE discriminator. Same value, same rule, same search string -- only the two
    # transformation priorities differ, and LOWERCASE first yields "Admin", not "admin".
    inverted = _stable_http(
        url, 200, timeout_s=_PROPAGATION_BUDGET_S, headers={"x-waf-tt": _ORDER_SENSITIVE},
        description=f"{_ORDER_SENSITIVE!r} to be SERVED under LOWERCASE-then-URL_DECODE")
    assert origin_marker in inverted[2], (
        f"{_ORDER_SENSITIVE!r} was still blocked after only the transformation ORDER changed, so "
        f"transformations are not applied in ascending Priority (LOWERCASE first yields 'Admin', "
        f"which does not EXACTLY match {_SEARCH!r}): status={inverted[0]!r} "
        f"body={inverted[2][:200]!r}"
    )

    # ---- leg 5: RESTORE -- swap back; the identical value is refused again.
    _replace_rules(w, acl_name, acl["Id"], [decode_first])
    again = _stable_http(
        url, 403, timeout_s=_PROPAGATION_BUDGET_S, headers={"x-waf-tt": _ORDER_SENSITIVE},
        description=f"{_ORDER_SENSITIVE!r} to be blocked again once the original order returns")
    assert again[0] == 403, (
        f"restoring URL_DECODE-then-LOWERCASE did not restore the block: status={again[0]!r} "
        f"body={again[2][:200]!r}"
    )

    attached = w.get_web_acl_for_resource(ResourceArn=stage_arn).get("WebACL") or {}
    assert attached.get("ARN") == acl_arn, (
        f"the WebACL detached itself between the legs, so the comparison is void: {attached!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
