"""wafv2-scope-down-statement-limits-a-managed-rule-group-to-a-uri-prefix."""
from __future__ import annotations

import random
import string
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wafv2-scope-down-statement-limits-a-managed-rule-group-to-a-uri-prefix"
GROUP = 'managed-rule-groups'
SERVICES = ['apigateway', 'wafv2']

# A check detail carrying this marker is graded as a data-plane failure, not a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

SCOPE = "REGIONAL"
ERR_NONEXISTENT = "WAFNonexistentItemException"
MANAGED_VENDOR = "AWS"
MANAGED_GROUP = "AWSManagedRulesSQLiRuleSet"
# A SQL-injection tautology in the QUERY STRING. It must not go in the path: API Gateway rejects
# some path characters before WAF is consulted, which would produce a 403 for the wrong reason.
SQLI_QUERY = "?q=" + urllib.parse.quote("1' OR '1'='1")

# Each budget bounds a poll on an observable condition; none is a sleep or an asserted deadline.
_ASSOCIATE_BUDGET_S = 420.0   # AssociateWebACL refuses a freshly created API Gateway stage with
# WAFUnavailableEntityException for roughly 40s.
_PROPAGATION_BUDGET_S = 360.0  # a rule change reached the API Gateway edge in 20-30s.

# CreateWebACL itself raises WAFUnavailableEntityException when a rule references an
# IPSet or RegexPatternSet created seconds earlier -- WAF's view of its OWN sub-resources is
# eventually consistent, not only its view of the protected resource.
_TRANSIENT = frozenset({"ThrottlingException", "WAFInternalErrorException",
                        "WAFOptimisticLockException", "WAFUnavailableEntityException"})


def _tok(n=10):
    """Lowercase alphanumeric token (apigateway stage names and WAF metric names reject hyphens)."""
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
    """Re-run fn until predicate holds. Raises AssertionError on expiry -- never Skips: a target
    that never reaches the expected state is the finding, not an environment limit."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = fn()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)

def _retry_transient(fn, *, timeout_s=240.0, interval_s=10.0):
    """Bounded retry over WAF's eventually-consistent control-plane codes only."""
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


# DeleteRestApi is throttled to roughly one call per 30s per account, and `ctx.on_cleanup`
# swallows the TooManyRequestsException, so teardown retries rather than leaking the REST API.
_API_DELETE_BUDGET_S = 420.0


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
    """The ARN AssociateWebACL takes for a REST API stage."""
    return f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}/stages/{stage}"


def _base_url(ctx, api_id, stage):
    """Invoke URL for a deployed stage: the real-AWS execute-api vhost, or the emulator's
    /_aws/execute-api/<id>/<stage>/ route."""
    return ctx.rest_api_url(api_id, stage)

def _create_web_acl(ctx, w, rules, **kwargs):
    name = "sim2realbehavwafacl" + _tok(10)
    summary = _retry_transient(lambda: w.create_web_acl(
        Name=name, Scope=SCOPE, DefaultAction={"Allow": {}}, Rules=rules,
        VisibilityConfig=_vis(name[:100]),
        Tags=[{"Key": "sim2real", "Value": CHECK},
              {"Key": "sim2real:managed", "Value": "true"}],
        **kwargs,
    ))["Summary"]
    ctx.on_cleanup(lambda: _delete_web_acl(w, name, summary["Id"]))
    return name, summary


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


def _replace_rules(w, name, acl_id, rules, **kwargs):
    """UpdateWebACL with a freshly fetched LockToken; returns the response."""
    def _once():
        token = w.get_web_acl(Name=name, Scope=SCOPE, Id=acl_id)["LockToken"]
        return w.update_web_acl(Name=name, Scope=SCOPE, Id=acl_id, LockToken=token,
                                DefaultAction={"Allow": {}}, Rules=rules,
                                VisibilityConfig=_vis(name[:100]), **kwargs)

    return _retry_transient(_once)

def _associate(ctx, w, acl_arn, resource_arn):
    """Associate, polling out WAFUnavailableEntityException while WAF's view of a freshly
    created API Gateway stage is still eventually consistent."""
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

def _statuses(url, n, *, headers=None, spacing_s=3.0):
    """n successive statuses from the edge, spaced by `spacing_s`.

    For asserting that EVERY observation holds; `spacing_s` is sample spacing, not a poll.
    """
    out = []
    for i in range(n):
        if i:
            time.sleep(spacing_s)
        out.append(_http("GET", url, headers=headers)[0])
    return out

def _stable_http(url, want, *, timeout_s, description, consecutive=4, headers=None,
                 method="GET", body=None, interval_s=5.0):
    """Poll until the edge answers `want` on `consecutive` SUCCESSIVE requests; return the last one.

    A WAF rule change reaches API Gateway's edge unevenly, so one matching answer is not settled.
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


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A ScopeDownStatement limits a managed SQLi rule group to /api/ paths: the same payload is
    refused in scope and served out of scope, until removing the scope-down refuses it there too.

    Reference: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-scope-down-statements.html
    """
    ag = ctx.client("apigateway")
    w = ctx.client("wafv2")

    origin_marker = "originmarker" + _tok(8)
    api_id = _create_api(ctx, ag)
    root = _root_id(ag, api_id)
    tpl = '{"origin":"%s","p":"$context.resourcePath"}' % origin_marker
    in_scope_parent = ag.create_resource(restApiId=api_id, parentId=root, pathPart="api")["id"]
    ctx.on_cleanup(lambda: ag.delete_resource(restApiId=api_id, resourceId=in_scope_parent))
    _mock(ag, api_id, in_scope_parent, "x", tpl)
    out_parent = ag.create_resource(restApiId=api_id, parentId=root, pathPart="public")["id"]
    ctx.on_cleanup(lambda: ag.delete_resource(restApiId=api_id, resourceId=out_parent))
    _mock(ag, api_id, out_parent, "x", tpl)
    stage = _deploy(ctx, ag, api_id)
    base = _base_url(ctx, api_id, stage)
    in_url, out_url = f"{base}/api/x", f"{base}/public/x"

    for url in (in_url, out_url):
        pre = _wait_http(url + SQLI_QUERY, lambda s, h, t: s == 200, timeout_s=180.0,
                         description=f"GET {url} to serve its MOCK integration")
        assert origin_marker in pre[2], (
            f"the origin did not answer {url} with the payload before WAF was attached, so a "
            f"later 403 could be API Gateway routing: {pre[0]!r} {pre[2][:200]!r}"
        )

    def _managed_rule(scope_down):
        statement = {"VendorName": MANAGED_VENDOR, "Name": MANAGED_GROUP}
        if scope_down:
            # WAF inspects the stage-qualified URI path, so STARTS_WITH "/api/" would never match.
            statement["ScopeDownStatement"] = {"ByteMatchStatement": {
                "SearchString": b"/api/",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS"}}
        return {"Name": "sqliscoped", "Priority": 0,
                "Statement": {"ManagedRuleGroupStatement": statement},
                "OverrideAction": {"None": {}},
                "VisibilityConfig": _vis("sqliscoped")}

    acl_name, acl = _create_web_acl(ctx, w, [_managed_rule(True)])
    stored = w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"])["WebACL"]["Rules"][0]
    assert "ScopeDownStatement" in stored["Statement"]["ManagedRuleGroupStatement"], (
        f"the scope-down was not stored on the rule, so every leg below would measure the "
        f"unscoped group: {stored['Statement']!r}"
    )
    _associate(ctx, w, acl["ARN"], _stage_arn(ctx, api_id, stage))

    # ---- leg 1: the payload INSIDE the scope-down is refused ----
    in_scope = _stable_http(
        in_url + SQLI_QUERY, 403, timeout_s=_PROPAGATION_BUDGET_S,
        description="the payload inside the scope-down predicate to be refused")
    assert in_scope[0] == 403, (
        f"the managed rule group did not evaluate a request inside its scope-down: "
        f"{in_scope[0]!r} {in_scope[2][:200]!r}"
    )

    # ---- leg 2: the IDENTICAL payload OUTSIDE the scope-down is served ----
    out_run = _statuses(out_url + SQLI_QUERY, 3)
    assert out_run == [200, 200, 200], (
        f"the identical payload was refused OUTSIDE the scope-down predicate, so the scope-down "
        f"is being ignored and the rule group evaluates everything: {out_run!r}"
    )
    out_body = _http("GET", out_url + SQLI_QUERY)
    assert origin_marker in out_body[2], (
        f"the out-of-scope request was allowed but did not reach the origin: "
        f"{out_body[2][:200]!r}"
    )

    # ---- leg 3: a BENIGN request inside the scope-down is served ----
    benign_run = _statuses(in_url, 3)
    assert benign_run == [200, 200, 200], (
        f"a benign request inside the scope-down was refused, so the 403 in leg 1 was not "
        f"payload-specific: {benign_run!r}"
    )

    # ---- leg 4: remove ONLY the scope-down; the same out-of-scope URL must now be refused ----
    _replace_rules(w, acl_name, acl["Id"], [_managed_rule(False)])
    unscoped = w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"])["WebACL"]["Rules"][0]
    assert "ScopeDownStatement" not in unscoped["Statement"]["ManagedRuleGroupStatement"], (
        f"the scope-down was not removed, so leg 4 repeats leg 2: {unscoped['Statement']!r}"
    )
    now_refused = _stable_http(
        out_url + SQLI_QUERY, 403, timeout_s=_PROPAGATION_BUDGET_S, consecutive=2,
        description="the out-of-scope payload to be refused once the scope-down is removed")
    assert now_refused[0] == 403, (
        f"removing the scope-down did not make the out-of-scope payload detectable, so leg 2's "
        f"200 was never evidence about the scope-down at all -- the rule group may simply not "
        f"detect this payload: {now_refused[0]!r} {now_refused[2][:200]!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
