"""wafv2-forwarded-ip-set-reference-blocks-by-header-position."""
from __future__ import annotations

import random
import string
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wafv2-forwarded-ip-set-reference-blocks-by-header-position"
GROUP = 'rule-evaluation'
SERVICES = ['apigateway', 'wafv2']

# A check detail carrying this marker is graded as a data-plane failure, not a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

SCOPE = "REGIONAL"
ERR_NONEXISTENT = "WAFNonexistentItemException"

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

def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))

def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0

def _poll(ctx, fn, predicate, *, timeout_s, interval_s=1.5, description="condition"):
    """Re-run fn until predicate holds. Raises AssertionError on expiry -- never Skips: a target
    that never reaches the expected state is the finding, not an environment limit."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = fn()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(f"{description} not observed within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)

def _retry_transient(fn, *, timeout_s=240.0, interval_s=2.0):
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

    outcome = _poll(ctx, _attempt, lambda o: o is True, timeout_s=_budget_s(ctx, _ASSOCIATE_BUDGET_S), interval_s=2.0,
                    description="AssociateWebACL to stop reporting the stage as unavailable")
    assert outcome is True, f"the WebACL could not be associated with the stage: {outcome!r}"
    ctx.on_cleanup(lambda: w.disassociate_web_acl(ResourceArn=resource_arn))

def _wait_http(ctx, url, predicate, *, timeout_s, description, method="GET", body=None, headers=None):
    """Poll the edge until predicate(status, headers, text). A never-answering endpoint is a
    data-plane FAIL, never a Skip: nothing answering at an address the target chose and claims to
    serve IS the data-plane failure this check exists to find."""
    seen = []

    def _once():
        res = _http(method, url, body=body, headers=headers)
        seen.append(res[0])
        return res

    try:
        return _poll(ctx, _once, lambda r: predicate(*r), timeout_s=timeout_s, interval_s=1.5,
                     description=description)
    except AssertionError as exc:
        if all(s is None for s in seen):
            raise AssertionError(
                f"{DATAPLANE_MARKER}: nothing answered at {url} within {timeout_s}s, so WAF rule "
                f"evaluation could not be observed at all"
            ) from exc
        raise

def _statuses(url, n, *, headers=None, spacing_s=1.0):
    """n successive statuses from the edge, spaced by `spacing_s`.

    For asserting that EVERY observation holds; `spacing_s` is sample spacing, not a poll.
    """
    out = []
    for i in range(n):
        if i:
            time.sleep(spacing_s)
        out.append(_http("GET", url, headers=headers)[0])
    return out

def _stable_http(ctx, url, want, *, timeout_s, description, consecutive=4, headers=None,
                 method="GET", body=None, interval_s=1.5):
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
        _poll(ctx, _once, lambda n: n >= consecutive, timeout_s=timeout_s, interval_s=interval_s,
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

def _delete_locked(w, kind, name, set_id, *, tolerate_missing=False):
    """Delete an IPSet / RegexPatternSet, refetching its LockToken (a stale one is rejected)."""
    getter, deleter = getattr(w, f"get_{kind}"), getattr(w, f"delete_{kind}")
    deadline = time.monotonic() + 240.0
    while True:
        try:
            token = getter(Name=name, Scope=SCOPE, Id=set_id)["LockToken"]
            deleter(Name=name, Scope=SCOPE, Id=set_id, LockToken=token)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == ERR_NONEXISTENT:
                if not tolerate_missing:
                    raise RuntimeError(
                        f"wafv2 {kind} {name} ({set_id}) already absent"
                    ) from exc
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"wafv2 {kind} {name} ({set_id}) not deleted: {code}"
                ) from exc
            time.sleep(5.0)


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """An IPSet rule with ForwardedIPConfig Position FIRST blocks only when the first
    X-Forwarded-For address is listed; unlisted, absent (NO_MATCH) and second-position pass.

    Reference: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-forwarded-ip-address.html
    """
    ag = ctx.client("apigateway")
    w = ctx.client("wafv2")

    # RFC 5737 documentation addresses, so nothing depends on the caller's own egress address.
    listed, unlisted = "198.51.100.7", "203.0.113.9"
    origin_marker = "originmarker" + _tok(8)

    api_id = _create_api(ctx, ag)
    _mock(ag, api_id, _root_id(ag, api_id), "xff", '{"origin":"%s"}' % origin_marker)
    stage = _deploy(ctx, ag, api_id)
    url = _base_url(ctx, api_id, stage) + "/xff"

    pre = _wait_http(ctx, url, lambda s, h, t: s == 200, timeout_s=_budget_s(ctx, 180.0),
                     description=f"GET {url} to serve its MOCK integration")
    assert origin_marker in pre[2], (
        f"the origin was not answering before WAF was attached: {pre[0]!r} {pre[2][:200]!r}"
    )

    ip_name = "sim2realbehavipset" + _tok(10)
    ipset = _retry_transient(lambda: w.create_ip_set(
        Name=ip_name, Scope=SCOPE, IPAddressVersion="IPV4",
        Addresses=[f"{listed}/32"],
        Description="sim2real-behav wafv2 forwarded-ip set",
        Tags=[{"Key": "sim2real", "Value": CHECK},
              {"Key": "sim2real:managed", "Value": "true"}],
    ))["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "ip_set", ip_name, ipset["Id"]))

    rule = {
        "Name": "xffblocker", "Priority": 0,
        "Statement": {"IPSetReferenceStatement": {
            "ARN": ipset["ARN"],
            "IPSetForwardedIPConfig": {"HeaderName": "X-Forwarded-For",
                                       "FallbackBehavior": "NO_MATCH",
                                       "Position": "FIRST"}}},
        "Action": {"Block": {}},
        "VisibilityConfig": _vis("xffblocker"),
    }
    acl_name, acl = _create_web_acl(ctx, w, [rule])
    _associate(ctx, w, acl["ARN"], _stage_arn(ctx, api_id, stage))

    # ---- leg 1: the listed address, alone in the header ----
    # A rule change reaches API Gateway's edge unevenly; a run of refusals shows the rule is live
    # before any allow-direction leg is read.
    match = _stable_http(ctx, url, 403, timeout_s=_budget_s(ctx, _PROPAGATION_BUDGET_S),
                         headers={"X-Forwarded-For": listed},
                         description="the listed forwarded address to be consistently blocked")
    assert match[0] == 403, (
        f"an address in the referenced IPSet, presented in the configured forwarded header, was "
        f"not blocked: {match[0]!r} {match[2][:200]!r}"
    )

    # ---- leg 2: an unlisted address -- the rule must not block everything ----
    other_run = _statuses(url, 3, headers={"X-Forwarded-For": unlisted})
    assert other_run == [200, 200, 200], (
        f"an address that is NOT in the IPSet was blocked, so the rule is not consulting the "
        f"set: {other_run!r}"
    )
    other = _http("GET", url, headers={"X-Forwarded-For": unlisted})
    assert origin_marker in other[2], (
        f"the unlisted address was allowed but did not reach the origin: {other[2][:200]!r}"
    )

    # ---- leg 3: no header at all -- FallbackBehavior NO_MATCH means allow ----
    absent_run = _statuses(url, 3)
    assert absent_run == [200, 200, 200], (
        f"a request with no X-Forwarded-For header was blocked, so FallbackBehavior NO_MATCH is "
        f"not honoured: {absent_run!r}"
    )

    # ---- leg 4: the listed address FIRST in a chain -- Position FIRST must match it ----
    first_in_chain = _stable_http(
        ctx, url, 403, timeout_s=_budget_s(ctx, _PROPAGATION_BUDGET_S), consecutive=3,
        headers={"X-Forwarded-For": f"{listed}, {unlisted}"},
        description="the listed address in the FIRST chain position to be matched")
    assert first_in_chain[0] == 403, (
        f"the listed address in the FIRST position of a forwarded chain was not matched: "
        f"{first_in_chain[0]!r} {first_in_chain[2][:200]!r}"
    )

    # ---- leg 5: the listed address SECOND -- Position FIRST must NOT match it ----
    second_run = _statuses(url, 3, headers={"X-Forwarded-For": f"{unlisted}, {listed}"})
    assert second_run == [200, 200, 200], (
        f"the listed address in the SECOND position was matched even though the rule specifies "
        f"Position FIRST, so the implementation scans the whole chain and is over-permissive in "
        f"the blocking direction: {second_run!r}"
    )
    second_body = _http("GET", url, headers={"X-Forwarded-For": f"{unlisted}, {listed}"})
    assert origin_marker in second_body[2], (
        f"the second-position request was allowed but did not reach the origin: "
        f"{second_body[2][:200]!r}"
    )

    stored = w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"])["WebACL"]["Rules"][0]
    assert stored["Statement"]["IPSetReferenceStatement"]["IPSetForwardedIPConfig"] == {
        "HeaderName": "X-Forwarded-For", "FallbackBehavior": "NO_MATCH", "Position": "FIRST"}, (
        f"the forwarded-IP configuration did not round-trip: {stored['Statement']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
