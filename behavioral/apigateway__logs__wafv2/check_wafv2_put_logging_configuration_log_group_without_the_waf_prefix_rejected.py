"""wafv2-put-logging-configuration-log-group-without-the-waf-prefix-rejected."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wafv2-put-logging-configuration-log-group-without-the-waf-prefix-rejected"
GROUP = 'logging'
SERVICES = ['apigateway', 'logs', 'wafv2']

# A check detail carrying this marker is graded as a data-plane failure, not a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

SCOPE = "REGIONAL"
ERR_NONEXISTENT = "WAFNonexistentItemException"
WAF_LOG_PREFIX = "aws-waf-logs-"
ERR_INVALID_PARAMETER = "WAFInvalidParameterException"
MSG_NONEXISTENT = "AWS WAF couldn’t perform the operation because your resource doesn’t exist."

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

def _error_of(fn):
    """The (code, message) of the AWS error fn raises. Raises AssertionError if fn SUCCEEDS -- an
    acceptance where real AWS refuses is the strongest possible signal."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code", ""), error.get("Message", "")
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

def _log_group(ctx, logs, name):
    """Create a log group and return (name, ARN). WAF wants the ARN WITHOUT the trailing ':*'
    that DescribeLogGroups appends, so the suffix is stripped rather than string-built."""
    logs.create_log_group(logGroupName=name,
                          tags={"sim2real": CHECK, "sim2real:managed": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    described = [g for g in logs.describe_log_groups(
        logGroupNamePrefix=name)["logGroups"] if g["logGroupName"] == name]
    assert described, f"the log group {name!r} was not readable after creation"
    arn = described[0]["arn"]
    return name, arn[:-2] if arn.endswith(":*") else arn


def _log_records(logs, group, marker, *, start_ms, timeout_s):
    """Every WAF log record in `group` whose httpRequest.uri carries `marker`, polled until at
    least one arrives. Paginated on nextToken: another run's records can fill page one."""
    def _scan():
        found, token = [], None
        while True:
            kwargs = {"logGroupName": group, "startTime": start_ms}
            if token:
                kwargs["nextToken"] = token
            page = logs.filter_log_events(**kwargs)
            for event in page.get("events", []):
                try:
                    record = json.loads(event["message"])
                except ValueError:
                    continue
                if marker in (record.get("httpRequest") or {}).get("uri", ""):
                    found.append(record)
            token = page.get("nextToken")
            if not token:
                return found

    return _poll(_scan, bool, timeout_s=timeout_s, interval_s=10.0,
                 description=f"a WAF log record naming {marker!r} to reach {group!r}")


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
    """WAF refuses a CloudWatch Logs destination whose group name lacks the aws-waf-logs- prefix,
    stores nothing and writes no streams there while blocking; the prefixed twin is accepted.

    Reference: https://docs.aws.amazon.com/waf/latest/developerguide/logging-cw-logs.html
    """
    ag = ctx.client("apigateway")
    logs = ctx.client("logs")
    w = ctx.client("wafv2")

    origin_marker = "originmarker" + _tok(8)
    path_marker = "logneg" + _tok(8)
    suffix = ctx.unique_name("sim2real-behav-wafv2-")
    bad_group, bad_arn = _log_group(ctx, logs, suffix)
    good_group, good_arn = _log_group(ctx, logs, WAF_LOG_PREFIX + suffix)
    assert not bad_group.startswith(WAF_LOG_PREFIX), (
        f"the 'bad' group name accidentally carries the required prefix: {bad_group!r}"
    )

    api_id = _create_api(ctx, ag)
    _mock(ag, api_id, _root_id(ag, api_id), path_marker, '{"origin":"%s"}' % origin_marker)
    stage = _deploy(ctx, ag, api_id)
    url = _base_url(ctx, api_id, stage) + "/" + path_marker

    pre = _wait_http(url, lambda s, h, t: s == 200, timeout_s=180.0,
                     description=f"GET {url} to serve its MOCK integration")
    assert origin_marker in pre[2], (
        f"the origin was not answering before WAF was attached: {pre[0]!r} {pre[2][:200]!r}"
    )

    rule_name = "logblocker"
    acl_name, acl = _create_web_acl(ctx, w, [{
        "Name": rule_name, "Priority": 0,
        "Statement": {"ByteMatchStatement": {
            "SearchString": path_marker.encode(),
            "FieldToMatch": {"UriPath": {}},
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            "PositionalConstraint": "CONTAINS"}},
        "Action": {"Block": {}},
        "VisibilityConfig": _vis(rule_name)}])
    _associate(ctx, w, acl["ARN"], _stage_arn(ctx, api_id, stage))

    redacted = [{"SingleHeader": {"Name": "authorization"}}]

    # ---- the negative leg: break exactly one thing -- the destination's name prefix ----
    code, message = _error_of(lambda: w.put_logging_configuration(LoggingConfiguration={
        "ResourceArn": acl["ARN"], "LogDestinationConfigs": [bad_arn],
        "RedactedFields": redacted}))
    assert code == ERR_INVALID_PARAMETER, (
        f"a CloudWatch Logs destination whose group name lacks {WAF_LOG_PREFIX!r} must be refused "
        f"with {ERR_INVALID_PARAMETER!r}, got {code!r}"
    )
    expected_message = (
        "Error reason: The ARN isn't valid. A valid ARN begins with arn: and includes other "
        f"information separated by colons or slashes., field: LOG_DESTINATION, parameter: {bad_arn}"
    )
    assert message == expected_message, f"{ERR_INVALID_PARAMETER} message {message!r}"

    # ---- effect absent, WAF's own view ----
    absent, absent_message = _error_of(lambda: w.get_logging_configuration(ResourceArn=acl["ARN"]))
    assert (absent, absent_message) == (ERR_NONEXISTENT, MSG_NONEXISTENT), (
        f"a refused PutLoggingConfiguration was stored anyway; GetLoggingConfiguration raised "
        f"{absent!r} {absent_message!r} instead of {ERR_NONEXISTENT!r}"
    )

    # ---- effect absent, in CloudWatch Logs, while the WebACL demonstrably blocks ----
    blocked = _stable_http(
        url, 403, timeout_s=_PROPAGATION_BUDGET_S, consecutive=2,
        headers={"authorization": "notasecret"},
        description="the marker path to be blocked, so there IS traffic that would be logged")
    assert blocked[0] == 403, (
        f"the request was not blocked, so 'no records were written' would be vacuous: "
        f"{blocked[0]!r} {blocked[2][:200]!r}"
    )
    streams = logs.describe_log_streams(logGroupName=bad_group).get("logStreams", [])
    assert streams == [], (
        f"the refused destination received log streams anyway, so WAF logged to a destination it "
        f"reported as invalid: {[s['logStreamName'] for s in streams]!r}"
    )

    # ---- positive control: the same call, prefixed group, must be accepted ----
    accepted = _retry_transient(lambda: w.put_logging_configuration(LoggingConfiguration={
        "ResourceArn": acl["ARN"], "LogDestinationConfigs": [good_arn],
        "RedactedFields": redacted}))
    ctx.on_cleanup(lambda: w.delete_logging_configuration(ResourceArn=acl["ARN"]))
    assert accepted["LoggingConfiguration"]["LogDestinationConfigs"] == [good_arn], (
        f"the accepted configuration did not echo its destination: "
        f"{accepted['LoggingConfiguration']!r}"
    )
    stored = w.get_logging_configuration(ResourceArn=acl["ARN"])["LoggingConfiguration"]
    assert stored["LogDestinationConfigs"] == [good_arn], (
        f"the accepted configuration is not readable back: {stored!r}"
    )
    assert stored["RedactedFields"] == redacted, (
        f"the accepted configuration lost its RedactedFields: {stored.get('RedactedFields')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
