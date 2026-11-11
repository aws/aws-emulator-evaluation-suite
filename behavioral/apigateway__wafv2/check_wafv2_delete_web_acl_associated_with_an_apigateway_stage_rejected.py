"""wafv2-delete-web-acl-associated-with-an-apigateway-stage-rejected."""
from __future__ import annotations

import random
import string
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wafv2-delete-web-acl-associated-with-an-apigateway-stage-rejected"
GROUP = 'webacl'
SERVICES = ['apigateway', 'wafv2']

# A check detail carrying this marker is graded as a data-plane failure, not a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

SCOPE = "REGIONAL"
ERR_NONEXISTENT = "WAFNonexistentItemException"
ERR_ASSOCIATED_ITEM = "WAFAssociatedItemException"
MSG_NONEXISTENT = "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."
MSG_ASSOCIATED_ITEM = ("AWS WAF couldn\u2019t perform the operation because your resource is being "
                       "used by another resource or it\u2019s associated with another resource.")

# Each budget bounds a poll on an observable condition; none is a sleep or an asserted deadline.
_ASSOCIATE_BUDGET_S = 420.0   # AssociateWebACL refuses a freshly created API Gateway stage with
# WAFUnavailableEntityException for roughly 40s.
_PROPAGATION_BUDGET_S = 360.0  # a rule change reached the API Gateway edge in 20-30s.
_UNREFERENCE_BUDGET_S = 360.0  # the reference bookkeeping behind
# WAFAssociatedItemException is itself eventually consistent after the disassociate.

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

def _error(fn):
    """The AWS error (code, message) fn raises. Raises AssertionError if fn SUCCEEDS -- an
    acceptance where real AWS refuses is the strongest possible signal."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("the call was ACCEPTED where a refusal was expected")

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


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:control",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Deleting a WebACL still associated with an API Gateway stage fails with
    WAFAssociatedItemException and it keeps blocking at the edge; after disassociation it deletes.
    """
    ag = ctx.client("apigateway")
    w = ctx.client("wafv2")

    origin_marker = "originmarker" + _tok(8)
    api_id = _create_api(ctx, ag)
    root = _root_id(ag, api_id)
    _mock(ag, api_id, root, "blocked", '{"origin":"%s"}' % origin_marker)
    _mock(ag, api_id, root, "allowed", '{"origin":"%s"}' % origin_marker)
    stage = _deploy(ctx, ag, api_id)
    base = _base_url(ctx, api_id, stage)
    blocked_url, allowed_url = f"{base}/blocked", f"{base}/allowed"

    pre = _wait_http(blocked_url, lambda s, h, t: s == 200, timeout_s=180.0,
                     description=f"GET {blocked_url} to serve its MOCK integration")
    assert origin_marker in pre[2], (
        f"the origin was not answering before WAF was attached: {pre[0]!r} {pre[2][:200]!r}"
    )

    rule = {
        "Name": "pathblocker", "Priority": 0,
        "Statement": {"ByteMatchStatement": {
            "SearchString": b"/blocked",
            "FieldToMatch": {"UriPath": {}},
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            "PositionalConstraint": "CONTAINS"}},
        "Action": {"Block": {}},
        "VisibilityConfig": _vis("pathblocker"),
    }
    acl_name, acl = _create_web_acl(ctx, w, [rule])
    stage_arn = _stage_arn(ctx, api_id, stage)
    _associate(ctx, w, acl["ARN"], stage_arn)

    # ---- prove the association is DOING something, and has SETTLED, before the delete ----
    # A WAF rule change reaches API Gateway's edge unevenly, so one 403 is not settled state.
    blocked = _stable_http(
        blocked_url, 403, timeout_s=_PROPAGATION_BUDGET_S,
        description="the matched path to be consistently blocked by the associated WebACL")
    allowed_run = _statuses(allowed_url, 3)
    assert blocked[0] == 403 and allowed_run == [200, 200, 200], (
        f"the WebACL was not governing the stage before the delete was attempted, so the refusal "
        f"would prove nothing: blocked={blocked[0]!r} allowed={allowed_run!r}"
    )

    # ---- the negative leg: break exactly one thing -- delete while still associated ----
    token_before = w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"])["LockToken"]
    code, message = _error(lambda: w.delete_web_acl(
        Name=acl_name, Scope=SCOPE, Id=acl["Id"], LockToken=token_before))
    assert (code, message) == (ERR_ASSOCIATED_ITEM, MSG_ASSOCIATED_ITEM), (
        f"deleting a WebACL that is still associated with an API Gateway stage must be refused "
        f"with {ERR_ASSOCIATED_ITEM!r} {MSG_ASSOCIATED_ITEM!r}, got {code!r} {message!r}"
    )

    # ---- effect absent, control plane ----
    still = w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"])
    assert still["LockToken"] == token_before, (
        f"a refused DeleteWebACL rotated the LockToken: {still['LockToken']!r} != "
        f"{token_before!r}"
    )
    assert [r["Name"] for r in still["WebACL"]["Rules"]] == ["pathblocker"], (
        f"the refused delete mutated the rule set: {still['WebACL']['Rules']!r}"
    )
    attached = w.get_web_acl_for_resource(ResourceArn=stage_arn).get("WebACL") or {}
    assert attached.get("ARN") == acl["ARN"], (
        f"the refused delete tore down the association it was refusing to break: {attached!r}"
    )

    # ---- effect absent, DATA plane: EVERY observation must still be a refusal ----
    still_blocked = _statuses(blocked_url, 3)
    assert still_blocked == [403, 403, 403], (
        f"the refused delete stopped the WebACL from enforcing, so the refusal protected "
        f"nothing: {still_blocked!r}"
    )

    # ---- positive control: disassociate, then the IDENTICAL delete must succeed ----
    w.disassociate_web_acl(ResourceArn=stage_arn)
    restored = _stable_http(
        blocked_url, 200, timeout_s=_PROPAGATION_BUDGET_S, consecutive=2,
        description="the path to stop being blocked once the WebACL is disassociated")
    assert origin_marker in restored[2], (
        f"disassociating restored a 200 that is not the origin's: {restored[2][:200]!r}"
    )

    def _delete_now():
        """True once the delete is accepted, else the refusal's error code (never falsy)."""
        token = w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"])["LockToken"]
        try:
            w.delete_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"], LockToken=token)
            return True
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code") or "<no error code>"

    outcome = _poll(_delete_now, lambda c: c is True, timeout_s=_UNREFERENCE_BUDGET_S,
                    interval_s=10.0,
                    description="the identical DeleteWebACL to succeed once disassociated")
    assert outcome is True, (
        f"deleting the same WebACL after disassociating it was still refused with {outcome!r}, "
        f"so the implementation refuses every delete"
    )
    gone = _error(lambda: w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"]))
    assert gone == (ERR_NONEXISTENT, MSG_NONEXISTENT), (
        f"the deleted WebACL is still readable; GetWebACL raised {gone!r} instead of "
        f"{(ERR_NONEXISTENT, MSG_NONEXISTENT)!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
