"""wafv2-managed-sqli-rule-group-refuses-a-payload-and-the-sample-names-the-rule."""
from __future__ import annotations

import ipaddress
import random
import string
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wafv2-managed-sqli-rule-group-refuses-a-payload-and-the-sample-names-the-rule"
GROUP = 'managed-rule-groups'
SERVICES = ['apigateway', 'wafv2']

# Marks a failure as an unimplemented data plane rather than a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

SCOPE = "REGIONAL"
ERR_NONEXISTENT = "WAFNonexistentItemException"
MANAGED_VENDOR = "AWS"
MANAGED_GROUP = "AWSManagedRulesSQLiRuleSet"
# A SQL-injection tautology in the QUERY STRING. It must not go in the path: API Gateway rejects
# some path characters before WAF is consulted, which would produce a 403 for the wrong reason.
SQLI_QUERY = "?q=" + urllib.parse.quote("1' OR '1'='1")

# Each budget bounds a poll for an observable condition; none is an asserted deadline.
_ASSOCIATE_BUDGET_S = 420.0   # AssociateWebACL refuses a freshly created API Gateway stage with
# WAFUnavailableEntityException for ~40s.
_PROPAGATION_BUDGET_S = 360.0  # a rule change reached the API Gateway edge in 20-30s.
_SAMPLE_BUDGET_S = 300.0  # sampling is a subset, so it is polled.

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

def _statuses(url, n, *, headers=None, spacing_s=3.0):
    """n successive statuses from the edge, spaced by `spacing_s`, for asserting every one holds."""
    out = []
    for i in range(n):
        if i:
            time.sleep(spacing_s)
        out.append(_http("GET", url, headers=headers)[0])
    return out

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


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """The SQLi managed group refuses a query-string tautology but serves the benign URL, and
    GetSampledRequests describes this run's blocked request, naming a rule the group declares.

    Reference: https://docs.aws.amazon.com/waf/latest/APIReference/API_GetSampledRequests.html
    """
    ag = ctx.client("apigateway")
    w = ctx.client("wafv2")

    origin_marker = "originmarker" + _tok(8)
    path_marker = "sqli" + _tok(8)

    api_id = _create_api(ctx, ag)
    _mock(ag, api_id, _root_id(ag, api_id), path_marker, '{"origin":"%s"}' % origin_marker)
    stage = _deploy(ctx, ag, api_id)
    base_path = f"/{path_marker}"
    url = _base_url(ctx, api_id, stage) + base_path

    pre = _wait_http(url + SQLI_QUERY, lambda s, h, t: s == 200, timeout_s=180.0,
                     description=f"GET {url} to serve its MOCK integration")
    assert origin_marker in pre[2], (
        f"the origin did not answer the payload-carrying URL before WAF was attached, so a later "
        f"403 could be API Gateway rejecting the query string: {pre[0]!r} {pre[2][:200]!r}"
    )

    rule = {
        "Name": "sqliset", "Priority": 0,
        "Statement": {"ManagedRuleGroupStatement": {
            "VendorName": MANAGED_VENDOR, "Name": MANAGED_GROUP}},
        "OverrideAction": {"None": {}},
        "VisibilityConfig": _vis("sqliset"),
    }
    acl_name, acl = _create_web_acl(ctx, w, [rule])
    _associate(ctx, w, acl["ARN"], _stage_arn(ctx, api_id, stage))

    # ---- the payload is refused ----
    blocked = _stable_http(
        url + SQLI_QUERY, 403, timeout_s=_PROPAGATION_BUDGET_S,
        description=f"the SQL-injection query string to be refused by {MANAGED_GROUP}")
    assert blocked[0] == 403, (
        f"a SQL-injection tautology in the query string was not refused by {MANAGED_GROUP}: "
        f"{blocked[0]!r} {blocked[2][:200]!r}"
    )
    assert origin_marker not in blocked[2], (
        f"the refused request still reached the origin: {blocked[2][:200]!r}"
    )

    # ---- the benign request on the SAME url must still be served ----
    benign_run = _statuses(url, 3)
    assert benign_run == [200, 200, 200], (
        f"a benign request to the same path was refused too, so the 403 above is not "
        f"payload-specific and the managed group is blocking everything: {benign_run!r}"
    )
    benign = _http("GET", url)
    assert origin_marker in benign[2], (
        f"the benign request was allowed but did not reach the origin: {benign[2][:200]!r}"
    )

    # ---- GetSampledRequests must describe THIS request ----
    samples = _poll(
        lambda: w.get_sampled_requests(
            WebAclArn=acl["ARN"], RuleMetricName="sqliset", Scope=SCOPE,
            TimeWindow={"StartTime": time.time() - 1800, "EndTime": time.time()},
            MaxItems=100),
        lambda d: any(path_marker in s["Request"].get("URI", "")
                      for s in d.get("SampledRequests", [])),
        timeout_s=_SAMPLE_BUDGET_S, interval_s=10.0,
        description="GetSampledRequests to return a sample naming this run's marker path")
    assert samples["PopulationSize"] > 0, (
        f"GetSampledRequests reported PopulationSize 0 for a rule that demonstrably refused a "
        f"request: {samples['PopulationSize']!r}"
    )
    hits = [s for s in samples["SampledRequests"] if path_marker in s["Request"].get("URI", "")]
    assert hits, f"no sample described this run's request: {samples['SampledRequests']!r}"
    sample = hits[0]

    assert sample["Action"] == "BLOCK", (
        f"the sample does not report the action WAF took: {sample['Action']!r}"
    )
    assert sample["Request"]["Method"] == "GET", (
        f"the sample reports the wrong request method: {sample['Request']!r}"
    )
    assert base_path in sample["Request"]["URI"], (
        f"the sample's URI does not contain the marker path {base_path!r}: "
        f"{sample['Request']['URI']!r}"
    )
    client_ip = sample["Request"].get("ClientIP", "")
    assert isinstance(ipaddress.ip_address(client_ip), ipaddress.IPv4Address), (
        f"Request.ClientIP is not an IPv4 address: {client_ip!r}"
    )
    header_names = {h["Name"].lower() for h in sample["Request"].get("Headers", [])}
    assert "host" in header_names, (
        f"the sample carries no Host header, so it is not describing a real HTTP request: "
        f"{sorted(header_names)!r}"
    )

    # ---- the terminating rule, DERIVED from the group's own declaration ----
    within = sample.get("RuleNameWithinRuleGroup") or ""
    parts = within.split("#")
    assert len(parts) == 3 and parts[0] == MANAGED_VENDOR and parts[1] == MANAGED_GROUP, (
        f"the sample does not attribute the refusal to a rule inside {MANAGED_GROUP} in the "
        f"documented <vendor>#<group>#<rule> form: {within!r}"
    )
    described = w.describe_managed_rule_group(
        VendorName=MANAGED_VENDOR, Name=MANAGED_GROUP, Scope=SCOPE)
    declared = {r["Name"] for r in described.get("Rules", [])}
    assert declared, f"DescribeManagedRuleGroup declared no rules at all: {described!r}"
    assert parts[2] in declared, (
        f"the terminating rule {parts[2]!r} is not among the rules "
        f"DescribeManagedRuleGroup declares for {MANAGED_GROUP}: {sorted(declared)!r}"
    )
    labels = [lbl["Name"] for lbl in described.get("AvailableLabels", [])]
    assert labels and all(n.startswith("awswaf:managed:aws:") for n in labels), (
        f"{MANAGED_GROUP} does not declare its labels under the managed-vendor namespace: "
        f"{labels!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
