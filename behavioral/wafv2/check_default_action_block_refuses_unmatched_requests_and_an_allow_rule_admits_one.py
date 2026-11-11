"""default-action-block-refuses-unmatched-requests-and-an-allow-rule-admits-one."""
from __future__ import annotations

import datetime
import random
import string
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "default-action-block-refuses-unmatched-requests-and-an-allow-rule-admits-one"
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

@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """DefaultAction Block refuses what no rule matches, and an Allow rule admits what it matches
    while a non-matching request is still refused in the same instant.
    """
    ag = ctx.client("apigateway")
    w = ctx.client("wafv2")

    prefix = "pfx" + _tok(8)
    origin_marker = "origin" + _tok(8)

    api_id = _create_api(ctx, ag)
    _mock(ag, api_id, _root_id(ag, api_id), "allowlist", '{"origin":"%s"}' % origin_marker)
    stage = _deploy(ctx, ag, api_id)
    url = _base_url(ctx, api_id, stage) + "/allowlist"
    stage_arn = _stage_arn(ctx, api_id, stage)

    pre = _wait_http(url, lambda s, h, t: s == 200, timeout_s=180.0,
                     description=f"GET {url} to serve its MOCK integration")
    assert origin_marker in pre[2], (
        f"the origin was not answering before WAF was attached, so nothing below proves "
        f"anything: status={pre[0]!r} body={pre[2][:200]!r}"
    )

    block_default = {"Block": {}}
    acl_name, acl = _create_web_acl(ctx, w, [], default_action=block_default)
    acl_arn = acl["ARN"]

    stored = w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"])["WebACL"]
    assert stored["DefaultAction"] == block_default, (
        f"the WebACL did not store DefaultAction Block, so leg 1 would test nothing: "
        f"{stored['DefaultAction']!r}"
    )
    assert stored.get("Rules") in ([], None), (
        f"the WebACL was created with rules it was not given, so leg 1's refusal could come from "
        f"a rule rather than the default action: {stored.get('Rules')!r}"
    )

    _associate(ctx, w, acl_arn, stage_arn)

    # ---- leg 1: the default action alone refuses everything.
    refused = _stable_http(
        url, 403, timeout_s=_PROPAGATION_BUDGET_S,
        headers={"x-waf-probe": "unmatched" + _tok(6)},
        description="every request to be refused by DefaultAction Block with no rules present")
    assert refused[0] == 403, (
        f"a WebACL whose DefaultAction is Block and which has NO rules still served the request, "
        f"so the default action is not consulted: status={refused[0]!r} "
        f"body={refused[2][:200]!r}"
    )
    assert origin_marker not in refused[2], (
        f"the refused request still reached the origin: {refused[2][:200]!r}"
    )

    # ---- leg 2: one Allow rule admits exactly what it matches.
    admit = {"Name": "admitrule", "Priority": 0,
             "Statement": _byte_match("x-waf-probe", prefix, constraint="STARTS_WITH"),
             "Action": {"Allow": {}}, "VisibilityConfig": _vis("admitrule")}
    _replace_rules(w, acl_name, acl["Id"], [admit], default_action=block_default)

    nonce = prefix + "-a" + _tok(6)
    admitted = _stable_http(
        url, 200, timeout_s=_PROPAGATION_BUDGET_S, headers={"x-waf-probe": nonce},
        description="the matching request to be admitted past a Block default action")
    assert origin_marker in admitted[2], (
        f"the Allow rule did not override the Block default action, or the admitted request did "
        f"not reach the origin: status={admitted[0]!r} body={admitted[2][:200]!r}"
    )
    sample = _sample_for(w, acl_arn, nonce, rule_metric="admitrule")
    assert sample.get("Action") == "ALLOW", (
        f"the admitted request was not attributed to the Allow rule: Action="
        f"{sample.get('Action')!r}, expected 'ALLOW'"
    )

    # ---- leg 3: TWIN CONTROL in the same instant -- a non-matching request is STILL refused.
    twin = _wait_http(
        url, lambda s, h, t: s == 403, timeout_s=120.0,
        headers={"x-waf-probe": "unmatched" + _tok(6)},
        description="a non-matching request to remain refused while the Allow rule is present")
    assert twin[0] == 403, (
        f"adding one Allow rule made an UNMATCHED request succeed too, so the default action "
        f"stopped applying: status={twin[0]!r} body={twin[2][:200]!r}"
    )
    assert origin_marker not in twin[2], (
        f"the unmatched request reached the origin despite a Block default action: "
        f"{twin[2][:200]!r}"
    )

    # ---- leg 4: RESTORE -- remove the Allow rule; the identical matching call is refused again.
    _replace_rules(w, acl_name, acl["Id"], [], default_action=block_default)
    again = _stable_http(
        url, 403, timeout_s=_PROPAGATION_BUDGET_S,
        headers={"x-waf-probe": prefix + "-b" + _tok(6)},
        description="the matching request to be refused again once the Allow rule is removed")
    assert again[0] == 403, (
        f"removing the Allow rule did not restore the Block default action: status={again[0]!r} "
        f"body={again[2][:200]!r}"
    )

    attached = w.get_web_acl_for_resource(ResourceArn=stage_arn).get("WebACL") or {}
    assert attached.get("ARN") == acl_arn, (
        f"the WebACL detached itself between the legs, so the comparison is void: {attached!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
