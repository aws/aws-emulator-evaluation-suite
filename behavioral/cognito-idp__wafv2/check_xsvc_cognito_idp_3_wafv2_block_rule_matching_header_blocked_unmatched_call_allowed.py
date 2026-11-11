"""xsvc-cognito-idp-3-wafv2-block-rule-matching-header-blocked-unmatched-call-allowed."""
from __future__ import annotations

import ipaddress
import random
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-idp-3-wafv2-block-rule-matching-header-blocked-unmatched-call-allowed"
GROUP = 'waf-association'
SERVICES = ['cognito-idp', 'wafv2']

PASSWORD = "Sup3r-Secret-Passw0rd!"
SCOPE = "REGIONAL"
ERR_NONEXISTENT = "WAFNonexistentItemException"
MARKER_HEADER = "x-sim2real-waf-marker"

# Every number below is a budget for a bounded poll to an OBSERVABLE condition, never a bare
# sleep and never an asserted deadline.
_ASSOCIATE_BUDGET_S = 300.0   # AssociateWebACL / the association taking effect at the API.
_PROPAGATION_BUDGET_S = 240.0  # a rule or action change reaching Cognito's enforcement point.
_SAMPLE_BUDGET_S = 240.0  # GetSampledRequests is a SUBSET even once populated, so it is polled.

_TRANSIENT = frozenset({"ThrottlingException", "WAFInternalErrorException",
                        "WAFOptimisticLockException", "WAFUnavailableEntityException"})


def _tok(n=10):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _vis(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}


def _poll(fn, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    while True:
        last = fn()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)


def _retry_transient(fn, *, timeout_s=180.0, interval_s=10.0):
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


def _create_web_acl(ctx, w, rules):
    name = "sim2realxsvcwafacl" + _tok(8)
    summary = _retry_transient(lambda: w.create_web_acl(
        Name=name, Scope=SCOPE, DefaultAction={"Allow": {}}, Rules=rules,
        VisibilityConfig=_vis(name[:100]),
        Tags=[{"Key": "sim2real", "Value": CHECK},
              {"Key": "sim2real:managed", "Value": "true"}],
    ))["Summary"]
    ctx.on_cleanup(lambda: _delete_web_acl(w, name, summary["Id"]))
    return name, summary


def _delete_web_acl(w, name, acl_id):
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


def _replace_rules(w, name, acl_id, rules):
    def _once():
        token = w.get_web_acl(Name=name, Scope=SCOPE, Id=acl_id)["LockToken"]
        return w.update_web_acl(Name=name, Scope=SCOPE, Id=acl_id, LockToken=token,
                                DefaultAction={"Allow": {}}, Rules=rules,
                                VisibilityConfig=_vis(name[:100]))

    return _retry_transient(_once)


def _associate(ctx, w, acl_arn, resource_arn):
    def _attempt():
        try:
            w.associate_web_acl(WebACLArn=acl_arn, ResourceArn=resource_arn)
            return True
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code", "UnknownError")

    outcome = _poll(_attempt, lambda o: o is True, timeout_s=_ASSOCIATE_BUDGET_S, interval_s=10.0,
                    description="AssociateWebACL to accept the user pool resource")
    assert outcome is True, f"the WebACL could not be associated with the user pool: {outcome!r}"
    ctx.on_cleanup(lambda: w.disassociate_web_acl(ResourceArn=resource_arn))


def _marked_initiate_auth(cog, client_id, username, marker):
    """Call InitiateAuth, injecting MARKER_HEADER (or none, if marker is None) via a before-send
    hook so WAF inspects a header no SDK call sets on its own. before-send runs AFTER SigV4
    signing, so adding an extra header here cannot invalidate the request signature -- WAF does
    not care whether a header it inspects was part of the signed set."""

    def _inject(request, **kwargs):
        if marker is not None:
            request.headers[MARKER_HEADER] = marker

    cog.meta.events.register("before-send.cognito-idp.InitiateAuth", _inject)
    try:
        return cog.initiate_auth(
            ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
        )
    finally:
        cog.meta.events.unregister("before-send.cognito-idp.InitiateAuth", _inject)


def _call_record(fn):
    """Normalize a boto3 call into (http_status, error_code, payload) without raising -- so it
    is safe to use as a `_poll` probe while WAF enforcement is still propagating and a call may
    legitimately succeed on one attempt and get refused on the next (or vice versa). Success is
    recorded as status 200 / code None / the call's own return value; a ClientError is recorded
    as its real HTTP status and error code."""
    try:
        result = fn()
        return 200, None, result
    except ClientError as exc:
        resp = exc.response
        status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return status, resp["Error"]["Code"], resp


@tags("axis:rejection", "cap:c7", "concern:e2e", "concern:negative-classes",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A REGIONAL WAFv2 web ACL associated with a Cognito user pool actually governs the pool's
    unauthenticated API operations (InitiateAuth here), and switching the governing rule's
    Action from BLOCK to COUNT changes enforcement on a LIVE association without re-associating.
    """
    cog = ctx.client("cognito-idp")
    w = ctx.client("wafv2")

    marker = "block-me-" + _tok(8)
    metric = "simxsvccip" + _tok(8)

    pool = cog.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-cip-waf-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"},
    )["UserPool"]
    pool_id, pool_arn = pool["Id"], pool["Arn"]
    ctx.on_cleanup(lambda _p=pool_id: cog.delete_user_pool(UserPoolId=_p))

    client_id = cog.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-xsvc-cip-waf-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: cog.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )

    username = ctx.unique_name("sim2real-xsvc-cip-waf-user-")
    cog.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: cog.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    cog.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )

    # ---- the origin works before any WAF is attached: a positive control for the setup itself ----
    pre = cog.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )
    assert "AuthenticationResult" in pre, (
        f"the user pool could not sign in before any WAF rule was attached, so nothing below "
        f"would be attributable to WAF: {pre!r}"
    )

    block_rule = {
        "Name": "blockonmarker", "Priority": 0,
        "Statement": {"ByteMatchStatement": {
            "FieldToMatch": {"SingleHeader": {"Name": MARKER_HEADER}},
            "PositionalConstraint": "EXACTLY",
            "SearchString": marker,
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
        }},
        "Action": {"Block": {}},
        "VisibilityConfig": _vis(metric),
    }
    acl_name, acl = _create_web_acl(ctx, w, [block_rule])
    _associate(ctx, w, acl["ARN"], pool_arn)

    # ---- (b)+(a): the marked call is refused, and the exact error/status is recorded ----
    status, code, resp = _poll(
        lambda: _call_record(lambda: _marked_initiate_auth(cog, client_id, username, marker)),
        lambda r: r[0] == 403,
        timeout_s=_PROPAGATION_BUDGET_S, interval_s=10.0,
        description="InitiateAuth carrying the marked header to be refused (403) by the BLOCK rule")
    assert code not in ("", None), f"a rejection carried no error code: {resp!r}"
    assert code == "ForbiddenException", f"the WAF block was refused as {code!r}: {resp!r}"
    assert resp["Error"].get("Message") == "Request not allowed due to WAF block.", resp["Error"]
    print(f"OBSERVED on real AWS: BLOCK -> HTTPStatusCode={status!r} Error.Code={code!r}")

    # ---- (c): the positive control, same pool/client/user, header simply absent ----
    unmatched_status, _unmatched_code, unmatched_resp = _poll(
        lambda: _call_record(lambda: _marked_initiate_auth(cog, client_id, username, None)),
        lambda r: r[0] == 200,
        timeout_s=120.0, interval_s=10.0,
        description="the unmatched call (no marker header) to succeed")
    assert unmatched_status == 200 and "AuthenticationResult" in unmatched_resp, (
        f"the unmatched call (no marker header) was refused too, so the BLOCK rule above is not "
        f"header-specific and is blocking everything: status={unmatched_status!r} {unmatched_resp!r}"
    )

    # ---- switch the SAME rule to COUNT on the LIVE association, no re-associate ----
    count_rule = dict(block_rule, Action={"Count": {}})
    _replace_rules(w, acl_name, acl["Id"], [count_rule])
    switch_time = time.time()

    allowed_status, _allowed_code, allowed_resp = _poll(
        lambda: _call_record(lambda: _marked_initiate_auth(cog, client_id, username, marker)),
        lambda r: r[0] == 200,
        timeout_s=_PROPAGATION_BUDGET_S, interval_s=10.0,
        description="the previously-blocked marked call to succeed once the rule is COUNT")
    assert allowed_status == 200 and "AuthenticationResult" in allowed_resp, (
        f"COUNT mode still refused the marked call: status={allowed_status!r} {allowed_resp!r}"
    )

    # ---- GetSampledRequests must describe a COUNT-mode hit on this run's rule. The BLOCK phase
    # above also sampled requests carrying this SAME marker header (the rule's SearchString did
    # not change, only its Action), and WAF's sampling pipeline has its own buffering lag -- a
    # BLOCK-phase sample can still surface with a timestamp past `switch_time`, so a time-window
    # cutoff alone is not a reliable discriminator. Select on Action == "COUNT" explicitly instead.
    def _count_hits(d):
        return [s for s in d.get("SampledRequests", [])
                if s.get("Action") == "COUNT"
                and any(h["Name"].lower() == MARKER_HEADER and h["Value"] == marker
                        for h in s.get("Request", {}).get("Headers", []))]

    samples = _poll(
        lambda: w.get_sampled_requests(
            WebAclArn=acl["ARN"], RuleMetricName=metric, Scope=SCOPE,
            TimeWindow={"StartTime": switch_time - 30, "EndTime": time.time()},
            MaxItems=500),
        lambda d: bool(_count_hits(d)),
        timeout_s=_SAMPLE_BUDGET_S, interval_s=10.0,
        description="GetSampledRequests to return a COUNT-action sample carrying this run's "
                     "marker header")
    assert samples["PopulationSize"] > 0, (
        f"GetSampledRequests reported PopulationSize 0 for a rule that demonstrably matched a "
        f"request: {samples['PopulationSize']!r}"
    )
    hits = _count_hits(samples)
    assert hits, f"no COUNT-action sample carried this run's marker header: " \
                 f"{samples['SampledRequests']!r}"
    # Attribution to THIS run's rule needs no extra field: GetSampledRequests was called with
    # RuleMetricName=metric, a per-run-unique metric name scoped to the single rule in this ACL,
    # so every sample it can return already belongs to that rule. `RuleNameWithinRuleGroup` is
    # absent here on purpose -- it names the leaf rule only when the terminating rule is nested
    # inside a managed/custom RULE GROUP, which this standalone WebACL-level rule is not.
    sample = hits[0]
    assert sample["Request"]["Method"] == "POST", (
        f"the sample reports the wrong request method: {sample['Request']!r}"
    )
    header_names = {h["Name"].lower() for h in sample["Request"].get("Headers", [])}
    assert "x-amz-target" in header_names, (
        f"the sample carries no x-amz-target header, so it is not describing a real signed "
        f"Cognito API request: {sorted(header_names)!r}"
    )
    client_ip = sample["Request"].get("ClientIP", "")
    # The model names no address family for ClientIP, so IPv6 is accepted as well.
    assert isinstance(ipaddress.ip_address(client_ip), ipaddress.IPv4Address) or isinstance(
        ipaddress.ip_address(client_ip), ipaddress.IPv6Address
    ), (
        f"Request.ClientIP is not an IP address, so the sample does not describe a real HTTP "
        f"request: {client_ip!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
