"""wafv2-label-match-statement-blocks-on-a-label-added-by-a-lower-priority-rule."""
from __future__ import annotations

import random
import string
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wafv2-label-match-statement-blocks-on-a-label-added-by-a-lower-priority-rule"
GROUP = 'rule-evaluation'
SERVICES = ['apigateway', 'wafv2']

# Marks a data-plane endpoint that answered nothing, so the failure reads as a missing data plane
# rather than as a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

SCOPE = "REGIONAL"
ERR_NONEXISTENT = "WAFNonexistentItemException"

# Every number below is a budget for a bounded poll to an OBSERVABLE condition, sized from real AWS
# timings -- never a sleep, and never a deadline that is asserted.
_ASSOCIATE_BUDGET_S = 420.0   # AssociateWebACL refuses a freshly created API Gateway stage with
# WAFUnavailableEntityException; it settled at 41.6s. 420 is ten times the measurement.
_PROPAGATION_BUDGET_S = 360.0  # a rule change reached the API Gateway edge in 20-30s.

# MEASURED: CreateWebACL itself raises WAFUnavailableEntityException when a rule references an
# IPSet or RegexPatternSet created seconds earlier -- WAF's view of its OWN sub-resources is
# eventually consistent, not only its view of the protected resource.
_TRANSIENT = frozenset({"ThrottlingException", "WAFInternalErrorException",
                        "WAFOptimisticLockException", "WAFUnavailableEntityException"})


# ===== helpers (self-contained) =====

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


# DeleteRestApi is throttled to roughly ONE call per 30s per ACCOUNT, so an unguarded delete in a
# teardown fails whenever two checks finish inside one window and the REST API leaks. The retry
# is part of the teardown rather than a nicety.
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
    """Associate, polling out WAFUnavailableEntityException. MEASURED: WAF's view of a freshly
    created API Gateway stage is eventually consistent and settled at 41.6s, so this is a bounded
    poll on the OBSERVABLE outcome and never a bare sleep."""
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
    """Poll until the edge answers `want` on `consecutive` SUCCESSIVE requests; return the last one.

    On AWS, a WAF rule change reaches API Gateway's edge unevenly. A
    403 was observed, and a request issued seconds later still returned 200 -- so a single
    observation of the expected state is not evidence that the state has settled. Requiring a run
    of identical answers is what makes a LATER single-request effect-absent assertion trustworthy
    instead of a race against propagation. Never a Skip: nothing answering at all is the
    data-plane failure this check exists to find.
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


# ===== end helpers =====


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A rule label added at priority 0 makes a LabelMatchStatement (bare label name) fire at
    priority 1: a request with the trigger header is blocked, the same request without it is
    served, and swapping the two priorities with byte-identical rules restores the 200."""
    ag = ctx.client("apigateway")
    w = ctx.client("wafv2")

    trigger_value = "tv" + _tok(8)
    origin_marker = "originmarker" + _tok(8)

    api_id = _create_api(ctx, ag)
    _mock(ag, api_id, _root_id(ag, api_id), "labelled",
          '{"origin":"%s"}' % origin_marker)
    stage = _deploy(ctx, ag, api_id)
    url = _base_url(ctx, api_id, stage) + "/labelled"

    pre = _wait_http(url, lambda s, h, t: s == 200, timeout_s=180.0,
                     description=f"GET {url} to serve its MOCK integration")
    assert origin_marker in pre[2], (
        f"the origin was not answering before WAF was attached, so nothing below proves "
        f"anything: {pre[0]!r} {pre[2][:200]!r}"
    )

    tagger = {
        "Name": "tagger", "Priority": 0,
        "Statement": {"ByteMatchStatement": {
            "SearchString": trigger_value.encode(),
            "FieldToMatch": {"SingleHeader": {"Name": "x-waf-probe"}},
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            "PositionalConstraint": "EXACTLY"}},
        "Action": {"Count": {}},
        "RuleLabels": [{"Name": "probelabel"}],
        "VisibilityConfig": _vis("tagger"),
    }
    blocker = {
        "Name": "blocker", "Priority": 1,
        "Statement": {"LabelMatchStatement": {"Scope": "LABEL", "Key": "probelabel"}},
        "Action": {"Block": {}},
        "VisibilityConfig": _vis("blocker"),
    }
    acl_name, acl = _create_web_acl(ctx, w, [tagger, blocker])

    # The label must be stored on the rule that ADDS it, and WAF must report the namespace it
    # will qualify it with -- read back, never assumed.
    stored = w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"])["WebACL"]
    stored_labels = [r.get("RuleLabels") for r in stored["Rules"] if r["Name"] == "tagger"][0]
    assert stored_labels == [{"Name": "probelabel"}], (
        f"the RuleLabels were not stored on the tagging rule: {stored_labels!r}"
    )
    # The account is taken out of the WebACL's own ARN rather than a second STS call, so the
    # namespace assertion is checked against the identity WAF itself minted the resource under.
    account = acl["ARN"].split(":")[4]
    namespace = stored.get("LabelNamespace")
    assert namespace == f"awswaf:{account}:webacl:{acl_name}:", (
        f"the WebACL reports an unexpected label namespace: {namespace!r} (account {account!r}, "
        f"web ACL {acl_name!r})"
    )
    consumer = [r for r in stored["Rules"] if r["Name"] == "blocker"][0]
    assert consumer["Statement"]["LabelMatchStatement"] == {"Scope": "LABEL",
                                                            "Key": "probelabel"}, (
        f"the consuming rule did not round-trip its unqualified LabelMatchStatement: "
        f"{consumer['Statement']!r}"
    )

    _associate(ctx, w, acl["ARN"], _stage_arn(ctx, api_id, stage))

    # ---- leg 1: no trigger header -> the tagger never fires, so no label, so no block ----
    no_header = _wait_http(
        url, lambda s, h, t: s == 200 and origin_marker in t, timeout_s=_PROPAGATION_BUDGET_S,
        description="a request without the trigger header to keep reaching the origin")
    assert no_header[0] == 200, (
        f"a request without the trigger header was blocked, so the block is not label-driven: "
        f"{no_header[0]!r} {no_header[2][:200]!r}"
    )

    # ---- leg 2: the trigger header -> tagger labels it -> blocker matches the label ----
    labelled = _stable_http(
        url, 403, timeout_s=_PROPAGATION_BUDGET_S, headers={"x-waf-probe": trigger_value},
        description="the labelled request to be blocked by the LabelMatchStatement")
    assert labelled[0] == 403, (
        f"a LabelMatchStatement did not fire on a label attached by an earlier-priority rule in "
        f"the same evaluation: got {labelled[0]!r} {labelled[2][:200]!r}"
    )
    assert origin_marker not in labelled[2], (
        f"the blocked request still reached the origin: {labelled[2][:200]!r}"
    )

    # ---- leg 3: identical rules, priorities SWAPPED -> the label does not exist yet ----
    swapped_blocker = dict(blocker, Priority=0)
    swapped_tagger = dict(tagger, Priority=1)
    _replace_rules(w, acl_name, acl["Id"], [swapped_blocker, swapped_tagger])
    reordered = w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"])["WebACL"]["Rules"]
    by_priority = {r["Priority"]: r["Name"] for r in reordered}
    assert by_priority == {0: "blocker", 1: "tagger"}, (
        f"the priority swap was not stored, so leg 3 would test the original order: "
        f"{by_priority!r}"
    )

    # Stability, not one observation: MEASURED, a rule change reaches API Gateway's edge
    # unevenly, so a lone 200 here could be a node that had not yet received EITHER rule set.
    reversed_leg = _stable_http(
        url, 200, timeout_s=_PROPAGATION_BUDGET_S, headers={"x-waf-probe": trigger_value},
        description="the labelled request to be allowed once the consumer runs FIRST")
    assert reversed_leg[0] == 200, (
        f"the Block rule still fired when it was evaluated BEFORE the rule that adds the label, "
        f"so labels are not scoped to evaluation order: got {reversed_leg[0]!r} "
        f"{reversed_leg[2][:200]!r}"
    )
    assert origin_marker in reversed_leg[2], (
        f"the request was allowed but did not reach the origin, so leg 3's 200 is not the "
        f"origin's: {reversed_leg[2][:200]!r}"
    )

    attached = w.get_web_acl_for_resource(
        ResourceArn=_stage_arn(ctx, api_id, stage)).get("WebACL") or {}
    assert attached.get("ARN") == acl["ARN"], (
        f"the WebACL detached itself between the legs, so leg 3 proves nothing: {attached!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
