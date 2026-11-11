"""wafv2-custom-request-handling-inserts-prefixed-headers-visible-to-the-origin."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wafv2-custom-request-handling-inserts-prefixed-headers-visible-to-the-origin"
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
_SAMPLE_BUDGET_S = 300.0  # GetSampledRequests content usually arrives within seconds,
# but sampling is a subset and is polled, not awaited.

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


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A Count rule's CustomRequestHandling header reaches the origin as x-amzn-waf-<name>, never
    the bare name and only for matching requests, and GetSampledRequests reports the same insert.

    Reference: https://docs.aws.amazon.com/waf/latest/developerguide/customizing-the-incoming-request.html
    """
    ag = ctx.client("apigateway")
    w = ctx.client("wafv2")

    origin_marker = "originmarker" + _tok(8)
    inserted_value = "insertedvalue" + _tok(8)
    trigger_value = "tv" + _tok(8)
    configured_name = "x-waf-inserted"
    prefixed_name = "x-amzn-waf-" + configured_name

    api_id = _create_api(ctx, ag)
    echo_tpl = (
        '{"origin":"' + origin_marker + '",'
        '"prefixed":"$input.params(\'' + prefixed_name + '\')",'
        '"bare":"$input.params(\'' + configured_name + '\')",'
        '"trigger":"$input.params(\'x-waf-trigger\')"}'
    )
    # The origin echoes the headers it received; only it can show what WAF inserted.
    _mock(ag, api_id, _root_id(ag, api_id), "echo", echo_tpl)
    stage = _deploy(ctx, ag, api_id)
    url = _base_url(ctx, api_id, stage) + "/echo"

    pre = _wait_http(url, lambda s, h, t: s == 200, timeout_s=180.0,
                     description=f"GET {url} to serve its echoing MOCK integration")
    assert json.loads(pre[2])["origin"] == origin_marker, (
        f"the echo origin was not answering before WAF was attached: {pre[2][:300]!r}"
    )

    rule = {
        "Name": "inserter", "Priority": 0,
        "Statement": {"ByteMatchStatement": {
            "SearchString": trigger_value.encode(),
            "FieldToMatch": {"SingleHeader": {"Name": "x-waf-trigger"}},
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            "PositionalConstraint": "EXACTLY"}},
        "Action": {"Count": {"CustomRequestHandling": {"InsertHeaders": [
            {"Name": configured_name, "Value": inserted_value}]}}},
        "VisibilityConfig": _vis("inserter"),
    }
    acl_name, acl = _create_web_acl(ctx, w, [rule])
    _associate(ctx, w, acl["ARN"], _stage_arn(ctx, api_id, stage))

    # ---- the triggered request: the origin must see the PREFIXED header ----
    triggered = _wait_http(
        url, lambda s, h, t: s == 200 and inserted_value in t,
        timeout_s=_PROPAGATION_BUDGET_S, headers={"x-waf-trigger": trigger_value},
        description="the inserted header to become visible to the origin")
    seen = json.loads(triggered[2])
    assert triggered[0] == 200, (
        f"a rule whose action is Count must not change the status: {triggered[0]!r}"
    )
    assert seen["trigger"] == trigger_value, (
        f"the origin did not even see the client's own trigger header, so the echo template is "
        f"not working and nothing below is meaningful: {seen!r}"
    )
    assert seen["prefixed"] == inserted_value, (
        f"CustomRequestHandling.InsertHeaders did not reach the origin as {prefixed_name!r}: "
        f"{seen!r}"
    )
    assert seen["bare"] == "", (
        f"WAF inserted the configured name {configured_name!r} verbatim instead of prefixing it "
        f"with 'x-amzn-waf-'; the origin saw both forms: {seen!r}"
    )

    # ---- the control: same URL, same WebACL, trigger header removed ----
    control = _http("GET", url)
    control_seen = json.loads(control[2])
    assert control[0] == 200, f"the control request was not served: {control[0]!r} {control[2]!r}"
    assert control_seen["prefixed"] == "" and control_seen["bare"] == "", (
        f"the inserted header reached the origin for a request that did NOT match the rule: "
        f"{control_seen!r}"
    )
    assert control_seen["origin"] == origin_marker, (
        f"the control request did not reach the origin: {control_seen!r}"
    )

    # ---- WAF's own account of the insertion must agree with what the origin received ----
    samples = _poll(
        lambda: w.get_sampled_requests(
            WebAclArn=acl["ARN"], RuleMetricName="inserter", Scope=SCOPE,
            TimeWindow={"StartTime": time.time() - 1800, "EndTime": time.time()},
            MaxItems=100),
        lambda d: any(s.get("RequestHeadersInserted") for s in d.get("SampledRequests", [])),
        timeout_s=_SAMPLE_BUDGET_S, interval_s=10.0,
        description="GetSampledRequests to report the headers WAF inserted")
    inserted_report = [
        h for s in samples["SampledRequests"] for h in (s.get("RequestHeadersInserted") or [])]
    assert {h["Name"] for h in inserted_report} == {prefixed_name}, (
        f"GetSampledRequests reports inserted header names that disagree with what the origin "
        f"saw: {inserted_report!r}"
    )
    assert all(h["Value"] == inserted_value for h in inserted_report), (
        f"GetSampledRequests reports a different inserted VALUE than the origin received: "
        f"{inserted_report!r}"
    )
    assert all(s["Action"] == "COUNT" for s in samples["SampledRequests"]), (
        f"the Count rule's samples do not report action COUNT: "
        f"{[s['Action'] for s in samples['SampledRequests']]!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
