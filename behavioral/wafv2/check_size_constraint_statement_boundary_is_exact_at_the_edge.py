"""size-constraint-statement-boundary-is-exact-at-the-edge."""
from __future__ import annotations

import datetime
import random
import string
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "size-constraint-statement-boundary-is-exact-at-the-edge"
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

    outcome = _poll(_attempt, lambda o: o is True, timeout_s=_ASSOCIATE_BUDGET_S, interval_s=15.0,
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
        return _poll(_once, lambda r: predicate(*r), timeout_s=timeout_s, interval_s=5.0,
                     description=description)
    except AssertionError as exc:
        if all(s is None for s in seen):
            raise AssertionError(
                f"{DATAPLANE_MARKER}: nothing answered at {url} within {timeout_s}s, so WAF rule "
                f"evaluation could not be observed at all"
            ) from exc
        raise


def _stable_http(url, want, *, timeout_s, description, consecutive=4, headers=None,
                 method="GET", body=None, interval_s=5.0):
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

    return _poll(_once, lambda s: s is not None, timeout_s=timeout_s, interval_s=15.0,
                 description=(f"a sampled request for rule metric {rule_metric!r} carrying the "
                              f"marker {marker!r}"))
# ===== end helpers =====

# The threshold is this check's own INPUT, not a service quota: it is chosen here and every
# expected outcome is derived from it arithmetically, so pinning it is correct.
_SIZE = 64


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A SizeConstraintStatement's GT threshold is exact and exclusive at the boundary byte
    (Size-1/Size/Size+1), and switching to LT inverts the verdicts.
    """
    ag = ctx.client("apigateway")
    w = ctx.client("wafv2")

    origin_marker = "origin" + _tok(8)

    api_id = _create_api(ctx, ag)
    _mock(ag, api_id, _root_id(ag, api_id), "sized", '{"origin":"%s"}' % origin_marker)
    stage = _deploy(ctx, ag, api_id)
    url = _base_url(ctx, api_id, stage) + "/sized"
    stage_arn = _stage_arn(ctx, api_id, stage)

    pre = _wait_http(url, lambda s, h, t: s == 200, timeout_s=180.0,
                     description=f"GET {url} to serve its MOCK integration")
    assert origin_marker in pre[2], (
        f"the origin was not answering before WAF was attached, so nothing below proves "
        f"anything: status={pre[0]!r} body={pre[2][:200]!r}"
    )

    def _value(length):
        """A header value of EXACTLY `length` ASCII bytes, ending in a per-call nonce so each
        request is individually attributable in GetSampledRequests."""
        nonce = _tok(8)
        assert length >= len(nonce), (
            f"a {length}-byte probe cannot carry an {len(nonce)}-byte attribution nonce; "
            f"_SIZE={_SIZE} is too small for this check's construction"
        )
        value = ("z" * (length - len(nonce))) + nonce
        assert len(value.encode()) == length, (
            f"the probe value is {len(value.encode())} bytes, expected exactly {length}; every "
            f"boundary assertion below derives its verdict from that length"
        )
        return value, nonce

    def _rule(operator):
        return {"Name": "sizerule", "Priority": 0,
                "Statement": {"SizeConstraintStatement": {
                    "FieldToMatch": {"SingleHeader": {"Name": "x-waf-size"}},
                    "ComparisonOperator": operator, "Size": _SIZE,
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}},
                "Action": {"Block": {}}, "VisibilityConfig": _vis("sizerule")}

    acl_name, acl = _create_web_acl(ctx, w, [_rule("GT")])
    acl_arn = acl["ARN"]
    stored = w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"])["WebACL"]["Rules"][0]
    stored_size = stored["Statement"]["SizeConstraintStatement"]["Size"]
    assert stored_size == _SIZE, (
        f"the WebACL stored a different threshold than the one every leg below derives its "
        f"expected outcome from: stored={stored_size!r}, sent={_SIZE!r}"
    )
    _associate(ctx, w, acl_arn, stage_arn)

    # ---- leg 1: Size+1 bytes -> strictly greater than the threshold -> BLOCK.
    over, over_nonce = _value(_SIZE + 1)
    blocked = _stable_http(
        url, 403, timeout_s=_PROPAGATION_BUDGET_S, headers={"x-waf-size": over},
        description=f"a {_SIZE + 1}-byte header value to be blocked by GT {_SIZE}")
    assert blocked[0] == 403, (
        f"a {_SIZE + 1}-byte header value was not blocked by SizeConstraint GT {_SIZE}, so the "
        f"size comparison is not performed: status={blocked[0]!r} body={blocked[2][:200]!r}"
    )
    assert origin_marker not in blocked[2], (
        f"the blocked request still reached the origin: {blocked[2][:200]!r}"
    )
    sample = _sample_for(w, acl_arn, over_nonce, rule_metric="sizerule")
    assert sample.get("Action") == "BLOCK", (
        f"the oversize request was not attributed as a BLOCK to the size rule: "
        f"Action={sample.get('Action')!r}"
    )

    # ---- leg 2: EXACTLY Size bytes -> NOT strictly greater -> served. This is the boundary,
    # and the only leg that separates GT from GE.
    at, _ = _value(_SIZE)
    at_edge = _wait_http(
        url, lambda s, h, t: s == 200, timeout_s=_PROPAGATION_BUDGET_S,
        headers={"x-waf-size": at},
        description=f"a header value of EXACTLY {_SIZE} bytes to be served by GT {_SIZE}")
    assert origin_marker in at_edge[2], (
        f"a header value of exactly {_SIZE} bytes was blocked by SizeConstraint GT {_SIZE}, so "
        f"the comparison is inclusive (GE) rather than strict: status={at_edge[0]!r} "
        f"body={at_edge[2][:200]!r}"
    )

    # ---- leg 3: Size-1 bytes -> served. Guards against "blocks everything".
    under, _ = _value(_SIZE - 1)
    below = _wait_http(
        url, lambda s, h, t: s == 200, timeout_s=120.0, headers={"x-waf-size": under},
        description=f"a {_SIZE - 1}-byte header value to be served by GT {_SIZE}")
    assert origin_marker in below[2], (
        f"a {_SIZE - 1}-byte header value was blocked by SizeConstraint GT {_SIZE}: "
        f"status={below[0]!r} body={below[2][:200]!r}"
    )

    # ---- leg 4: break exactly one thing -- the operator. GT -> LT must INVERT both verdicts.
    _replace_rules(w, acl_name, acl["Id"], [_rule("LT")])
    stored_op = (w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"])["WebACL"]["Rules"][0]
                 ["Statement"]["SizeConstraintStatement"]["ComparisonOperator"])
    assert stored_op == "LT", (
        f"the operator flip was not stored, so leg 4 would re-test GT: {stored_op!r}"
    )

    under2, under2_nonce = _value(_SIZE - 1)
    now_blocked = _stable_http(
        url, 403, timeout_s=_PROPAGATION_BUDGET_S, headers={"x-waf-size": under2},
        description=f"a {_SIZE - 1}-byte header value to be blocked once the operator is LT")
    assert now_blocked[0] == 403, (
        f"flipping ComparisonOperator to LT did not make a {_SIZE - 1}-byte value match, so the "
        f"operator is ignored: status={now_blocked[0]!r} body={now_blocked[2][:200]!r}"
    )
    lt_sample = _sample_for(w, acl_arn, under2_nonce, rule_metric="sizerule")
    assert lt_sample.get("Action") == "BLOCK", (
        f"the undersize request was not attributed as a BLOCK under LT: "
        f"Action={lt_sample.get('Action')!r}"
    )
    over2, _ = _value(_SIZE + 1)
    now_served = _wait_http(
        url, lambda s, h, t: s == 200, timeout_s=_PROPAGATION_BUDGET_S,
        headers={"x-waf-size": over2},
        description=f"a {_SIZE + 1}-byte header value to be served once the operator is LT")
    assert origin_marker in now_served[2], (
        f"a {_SIZE + 1}-byte value was still blocked under LT {_SIZE}, so the outcome does not "
        f"track the operator: status={now_served[0]!r} body={now_served[2][:200]!r}"
    )

    # ---- leg 5: RESTORE -- back to GT; the oversize request is refused again.
    _replace_rules(w, acl_name, acl["Id"], [_rule("GT")])
    over3, _ = _value(_SIZE + 1)
    again = _stable_http(
        url, 403, timeout_s=_PROPAGATION_BUDGET_S, headers={"x-waf-size": over3},
        description=f"a {_SIZE + 1}-byte header value to be blocked again once GT is restored")
    assert again[0] == 403, (
        f"restoring ComparisonOperator GT did not restore the refusal: status={again[0]!r} "
        f"body={again[2][:200]!r}"
    )

    attached = w.get_web_acl_for_resource(ResourceArn=stage_arn).get("WebACL") or {}
    assert attached.get("ARN") == acl_arn, (
        f"the WebACL detached itself between the legs, so the comparison is void: {attached!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
