"""wafv2-rate-based-rule-refuses-the-caller-lists-its-key-then-recovers."""
from __future__ import annotations

import ipaddress
import random
import string
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wafv2-rate-based-rule-refuses-the-caller-lists-its-key-then-recovers"
GROUP = 'traffic'
SERVICES = ['apigateway', 'wafv2']

# Marks a failure as an unimplemented data plane rather than a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

SCOPE = "REGIONAL"
ERR_NONEXISTENT = "WAFNonexistentItemException"
RATE_LIMIT = 10  # the model's RateLimit minimum, which is what makes a short flood
# sufficient rather than needing tens of thousands of requests
WINDOW_S = 60    # the shortest EvaluationWindowSec WAF accepts
BURST = 60       # 6x the limit, issued as fast as the runner can

# Each budget bounds a poll for an observable condition; none is an asserted deadline.
_ASSOCIATE_BUDGET_S = 420.0   # AssociateWebACL refuses a freshly created API Gateway stage with
# WAFUnavailableEntityException for ~40s.
_PROPAGATION_BUDGET_S = 360.0  # a rule change reached the API Gateway edge in 20-30s.
_FLOOD_BUDGET_S = 420.0  # WAF's rate aggregation lags the traffic it counts, so the
# flood must keep asking, not just count.
_MANAGED_KEYS_BUDGET_S = 300.0
_SAMPLE_BUDGET_S = 300.0
_RECOVERY_BUDGET_S = 420.0  # one request per poll interval keeps the source well
# under Limit=10, so the window drains while the poll watches for the 200.

# CreateWebACL raises WAFUnavailableEntityException when a rule references an IPSet or
# RegexPatternSet created seconds earlier: WAF's view of its own sub-resources is eventually consistent.
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
    """Re-run fn until predicate holds; raise AssertionError on expiry."""
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


# DeleteRestApi is throttled to roughly one call per 30s per account, so the teardown retries
# TooManyRequestsException rather than leaking the API.
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
    """Invoke URL for a deployed stage."""
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
    """Associate, polling out WAFUnavailableEntityException: WAF's view of a freshly created
    API Gateway stage is eventually consistent."""
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
    """Poll the edge until predicate(status, headers, text); nothing answering is a data-plane FAIL."""
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
    """Poll until the edge answers `want` on `consecutive` successive requests; return the last one.

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


# timing:real-time — cooldown: 60 s https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based-high-level-settings.html
@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c1",
      "timing:real-time")
def run(ctx) -> None:
    """A rate-based rule refuses a source only after Limit requests, lists it in the managed keys
    (matching a sampled blocked ClientIP), then serves it again once the window drains.

    Reference: https://docs.aws.amazon.com/waf/latest/APIReference/API_GetRateBasedStatementManagedKeys.html
    """
    ag = ctx.client("apigateway")
    w = ctx.client("wafv2")

    origin_marker = "originmarker" + _tok(8)
    api_id = _create_api(ctx, ag)
    _mock(ag, api_id, _root_id(ag, api_id), "flood", '{"origin":"%s"}' % origin_marker)
    stage = _deploy(ctx, ag, api_id)
    url = _base_url(ctx, api_id, stage) + "/flood"

    pre = _wait_http(url, lambda s, h, t: s == 200, timeout_s=180.0,
                     description=f"GET {url} to serve its MOCK integration")
    assert origin_marker in pre[2], (
        f"the origin was not answering before WAF was attached: {pre[0]!r} {pre[2][:200]!r}"
    )

    rule_name = "rater"
    acl_name, acl = _create_web_acl(ctx, w, [{
        "Name": rule_name, "Priority": 0,
        "Statement": {"RateBasedStatement": {
            "Limit": RATE_LIMIT, "AggregateKeyType": "IP", "EvaluationWindowSec": WINDOW_S}},
        "Action": {"Block": {}},
        "VisibilityConfig": _vis(rule_name)}])
    _associate(ctx, w, acl["ARN"], _stage_arn(ctx, api_id, stage))

    # ---- baseline: the rule is attached and NOT refusing before any load ----
    baseline = _stable_http(
        url, 200, timeout_s=_PROPAGATION_BUDGET_S, consecutive=3,
        description="the stage to answer under an idle rate-based rule")
    assert origin_marker in baseline[2], (
        f"the baseline 200 is not the origin's: {baseline[2][:200]!r}"
    )

    # ---- drive the source over the limit, then keep asking until WAF catches up ----
    # A burst drives the 60s window far past Limit=10; the slower tail (30 requests/minute)
    # holds it there while WAF's aggregation catches up.
    statuses = [_http("GET", url)[0] for _ in range(BURST)]
    deadline = time.monotonic() + _FLOOD_BUDGET_S
    while 403 not in statuses and time.monotonic() < deadline:
        time.sleep(2.0)
        statuses.append(_http("GET", url)[0])
    assert 403 in statuses, (
        f"a rate-based rule with Limit={RATE_LIMIT} over a {WINDOW_S}s window never refused a "
        f"request across {len(statuses)} sequential requests from one source in "
        f"{_FLOOD_BUDGET_S}s: distinct statuses seen were {sorted(set(statuses), key=str)!r}"
    )
    first_refusal = statuses.index(403)
    assert first_refusal >= RATE_LIMIT, (
        f"request #{first_refusal + 1} was refused, which is at or below the configured Limit of "
        f"{RATE_LIMIT}, so the refusal cannot be rate-based: {statuses[:RATE_LIMIT + 2]!r}"
    )

    # ---- the managed-keys API must name the throttled source, not an empty list ----
    keys = _poll(
        lambda: w.get_rate_based_statement_managed_keys(
            Scope=SCOPE, WebACLName=acl_name, WebACLId=acl["Id"], RuleName=rule_name),
        lambda d: bool((d.get("ManagedKeysIPV4") or {}).get("Addresses")),
        timeout_s=_MANAGED_KEYS_BUDGET_S, interval_s=15.0,
        description="GetRateBasedStatementManagedKeys to report the throttled source")
    addresses = keys["ManagedKeysIPV4"]["Addresses"]
    assert keys["ManagedKeysIPV4"]["IPAddressVersion"] == "IPV4", (
        f"the IPv4 managed-key block does not declare IPV4: {keys['ManagedKeysIPV4']!r}"
    )
    managed = set()
    for entry in addresses:
        network = ipaddress.ip_network(entry, strict=False)
        assert isinstance(network, ipaddress.IPv4Network), (
            f"an IPv4 managed key is not an IPv4 network: {entry!r}"
        )
        managed.add(str(network.network_address))

    # ---- cross-plane: the throttled address must be one the SAMPLING api attributes to us ----
    samples = _poll(
        lambda: w.get_sampled_requests(
            WebAclArn=acl["ARN"], RuleMetricName=rule_name, Scope=SCOPE,
            TimeWindow={"StartTime": time.time() - 1800, "EndTime": time.time()},
            MaxItems=100),
        lambda d: any(s.get("Action") == "BLOCK" for s in d.get("SampledRequests", [])),
        timeout_s=_SAMPLE_BUDGET_S, interval_s=10.0,
        description="GetSampledRequests to report a request the rate-based rule refused")
    sampled_ips = {s["Request"]["ClientIP"] for s in samples["SampledRequests"]
                   if s.get("Action") == "BLOCK"}
    assert managed & sampled_ips, (
        f"no address in GetRateBasedStatementManagedKeys {sorted(managed)!r} matches any source "
        f"GetSampledRequests attributes a refusal to {sorted(sampled_ips)!r}, so the two APIs "
        f"disagree about who was throttled"
    )

    # ---- the window drains: at one request per poll the source falls back under the limit ----
    # 20s between requests is 3 per minute: comfortably under Limit=10, so the poll itself
    # cannot hold the window over the limit and prevent the recovery it is watching for.
    recovered = _stable_http(
        url, 200, timeout_s=_RECOVERY_BUDGET_S, consecutive=2, interval_s=20.0,
        description=f"the source to be served again once its {WINDOW_S}s window drains below "
                    f"Limit={RATE_LIMIT}")
    assert origin_marker in recovered[2], (
        f"recovery produced a 200 that is not the origin's: {recovered[2][:200]!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
