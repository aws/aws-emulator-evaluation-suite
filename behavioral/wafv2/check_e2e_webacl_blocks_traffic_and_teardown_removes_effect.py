"""e2e-webacl-blocks-traffic-and-teardown-removes-effect."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-webacl-blocks-traffic-and-teardown-removes-effect"
GROUP = "e2e"
SERVICES = ["wafv2"]

#: WAFNonexistentItemException's message for a deleted web ACL.
NONEXISTENT_MESSAGE = (
    "AWS WAF couldn’t perform the operation because your resource doesn’t exist."
)


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A WebACL referencing a RuleGroup with an IPSet rule blocks the associated resource (403) and samples BLOCK
    requests attributed to the nested rule; after disassociation the resource answers 200, and the deleted WebACL's read
    and update fail with WAFNonexistentItemException and the exact message.
    """
    wafv2 = ctx.client("wafv2")
    teardown_deadline: dict = {}
    api = _create_mock_rest_api(ctx, ["check"])
    member_cidr = "203.0.113.0/24"  # RFC 5737 TEST-NET-3

    ipset_name = ctx.unique_name("sim2real-wafv2-ipset-")
    ipset = wafv2.create_ip_set(
        Name=ipset_name,
        Scope="REGIONAL",
        IPAddressVersion="IPV4",
        Addresses=[member_cidr],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Summary"]
    ctx.on_cleanup(
        lambda: _delete_when_unreferenced(
            teardown_deadline,
            lambda: wafv2.get_ip_set(Name=ipset_name, Scope="REGIONAL", Id=ipset["Id"])["LockToken"],
            lambda token: wafv2.delete_ip_set(Name=ipset_name, Scope="REGIONAL", Id=ipset["Id"], LockToken=token),
        )
    )

    rulegroup_name = ctx.unique_name("sim2real-wafv2-rulegroup-")
    inner_metric = "InnerBlockRuleMetric"
    # The IPSet ARN just created above can take a short while to become resolvable by
    # other WAFv2 operations that reference it (WAFUnavailableEntityException: "AWS
    # WAF couldn't retrieve the resource") -- poll through that propagation window.
    rulegroup = _retry_unavailable(
        lambda: wafv2.create_rule_group(
            Name=rulegroup_name,
            Scope="REGIONAL",
            Capacity=10,
            Rules=[
                {
                    "Name": "InnerBlockRule",
                    "Priority": 0,
                    "Action": {"Block": {}},
                    "Statement": {
                        "IPSetReferenceStatement": {
                            "ARN": ipset["ARN"],
                            "IPSetForwardedIPConfig": {
                                "HeaderName": "X-Forwarded-For",
                                "FallbackBehavior": "NO_MATCH",
                                "Position": "FIRST",
                            },
                        }
                    },
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": inner_metric,
                    },
                }
            ],
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": rulegroup_name,
            },
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )["Summary"]

    ctx.on_cleanup(
        lambda: _delete_when_unreferenced(
            teardown_deadline,
            lambda: wafv2.get_rule_group(Name=rulegroup_name, Scope="REGIONAL", Id=rulegroup["Id"])["LockToken"],
            lambda token: wafv2.delete_rule_group(
                Name=rulegroup_name, Scope="REGIONAL", Id=rulegroup["Id"], LockToken=token
            ),
        )
    )

    webacl_name = ctx.unique_name("sim2real-wafv2-webacl-")
    outer_metric = "RuleGroupRefMetric"
    webacl = _retry_unavailable(
        lambda: wafv2.create_web_acl(
            Name=webacl_name,
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            Rules=[
                {
                    "Name": "RuleGroupRefRule",
                    "Priority": 0,
                    "OverrideAction": {"None": {}},
                    "Statement": {"RuleGroupReferenceStatement": {"ARN": rulegroup["ARN"]}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": outer_metric,
                    },
                }
            ],
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": webacl_name,
            },
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )["Summary"]

    webacl_id = webacl["Id"]
    webacl_arn = webacl["ARN"]
    ctx.on_cleanup(lambda: _safe(lambda: wafv2.disassociate_web_acl(ResourceArn=api["stage_arn"])))
    ctx.on_cleanup(
        lambda: _delete_when_unreferenced(
            teardown_deadline,
            lambda: wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id)["LockToken"],
            lambda token: wafv2.delete_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id, LockToken=token),
        )
    )

    _retry_unavailable(lambda: wafv2.associate_web_acl(WebACLArn=webacl_arn, ResourceArn=api["stage_arn"]))

    blocked_headers = {"X-Forwarded-For": "203.0.113.10"}
    blocked_status = _poll_until(
        lambda: _http_get(api["invoke_url"] + "/check", headers=blocked_headers),
        lambda status: status == 403,
        timeout_s=150.0,
        interval_s=5.0,
    )
    assert blocked_status == 403, f"expected the resource to be governed and block, got {blocked_status}"

    from datetime import datetime, timedelta, timezone

    # GetSampledRequests returns a statistical SAMPLE, not a guaranteed log of every
    # matched request -- capturing one can take both traffic volume and a queryability
    # delay. Keep generating blocked traffic WHILE polling so the sample window is
    # continuously fed, with a generous overall timeout.
    def _probe_with_traffic():
        for _ in range(10):
            _http_get(api["invoke_url"] + "/check", headers=blocked_headers)
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=2)
        return wafv2.get_sampled_requests(
            WebAclArn=webacl_arn,
            RuleMetricName=outer_metric,
            Scope="REGIONAL",
            TimeWindow={"StartTime": start, "EndTime": end},
            MaxItems=500,
        )["SampledRequests"]

    samples = _poll_until(
        _probe_with_traffic,
        lambda samples: len(samples) > 0,
        timeout_s=300.0,
        interval_s=15.0,
    )
    assert samples, "no sampled requests recorded for the rule-group-referencing rule"

    assert all(s["Action"] == "BLOCK" for s in samples), (
        f"expected every sampled request to be BLOCKed, got actions "
        f"{[s.get('Action') for s in samples]}"
    )
    # AWS qualifies the nested rule name with the rule group's own name:
    # "{RuleGroupName}#{RuleName}".
    expected_suffix = f"{rulegroup_name}#InnerBlockRule"
    assert any(s.get("RuleNameWithinRuleGroup") == expected_suffix for s in samples), (
        f"expected at least one sample attributed to {expected_suffix!r}, got "
        f"{[s.get('RuleNameWithinRuleGroup') for s in samples]}"
    )


    # Teardown: disassociate and confirm the resource is no longer governed.
    wafv2.disassociate_web_acl(ResourceArn=api["stage_arn"])
    unblocked_status = _poll_until(
        lambda: _http_get(api["invoke_url"] + "/check", headers=blocked_headers),
        lambda status: status == 200,
        timeout_s=150.0,
        interval_s=5.0,
    )
    assert unblocked_status == 200, (
        f"expected the same previously-blocked request to pass through after "
        f"disassociation, got {unblocked_status}"
    )

    current = wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id)
    wafv2.delete_web_acl(
        Name=webacl_name, Scope="REGIONAL", Id=webacl_id, LockToken=current["LockToken"]
    )
    read_code, read_message = _error(lambda: wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id))
    assert read_code == "WAFNonexistentItemException", (
        f"expected an independent read of the deleted WebACL to raise "
        f"WAFNonexistentItemException, got {read_code!r}"
    )
    assert read_message == NONEXISTENT_MESSAGE, read_message

    # The delete must also make the id unusable for a mutation, not just for a read.
    mutate_code, mutate_message = _error(
        lambda: wafv2.update_web_acl(
            Name=webacl_name,
            Scope="REGIONAL",
            Id=webacl_id,
            DefaultAction={"Allow": {}},
            Rules=[],
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": webacl_name,
            },
            LockToken=current["LockToken"],
        )
    )
    assert mutate_code == "WAFNonexistentItemException", (
        f"expected UpdateWebACL against the deleted id to raise "
        f"WAFNonexistentItemException, got {mutate_code!r}"
    )
    assert mutate_message == NONEXISTENT_MESSAGE, mutate_message


# budget.cleanup_timeout for behavioral/wafv2, one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 900.0


def _delete_when_unreferenced(deadline, lock_token, delete) -> None:
    """Delete a WAFv2 resource with a freshly read LockToken. Done when the delete succeeds or the
    resource is gone; WAFAssociatedItemException (a reference still propagating) and
    WAFOptimisticLockException are retried every 2 s to the shared cleanup deadline; anything else
    raises."""
    end = deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    while True:
        try:
            delete(lock_token())
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "WAFNonexistentItemException":
                return
            if code not in ("WAFAssociatedItemException", "WAFOptimisticLockException") or time.monotonic() >= end:
                raise
        time.sleep(2)


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


def _error(fn):
    """Call fn(); return (code, message) of its botocore error. A call that succeeds raises
    AssertionError: the caller expects a refusal."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_mock_rest_api(ctx, paths):
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-wafv2-api-"),
        tags={"sim2real": CHECK},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    for path in paths:
        resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart=path)["id"]
        apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
        apigw.put_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            type="MOCK",
            requestTemplates={"application/json": '{"statusCode": 200}'},
        )
        apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
        apigw.put_integration_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            statusCode="200",
            responseTemplates={"application/json": ""},
        )
    stage_name = "test"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    region = ctx.region
    return {
        "api_id": api_id,
        "stage_arn": f"arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{stage_name}",
        "invoke_url": ctx.rest_api_url(api_id, stage_name),
    }


def _http_get(url, headers=None, timeout=10):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError:
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _retry_unavailable(fn, *, timeout_s=300.0, interval_s=2.0):
    """A just-created WAFv2/API-Gateway resource can be transiently unresolvable to a
    dependent WAFv2 call (WAFUnavailableEntityException: "AWS WAF couldn't retrieve
    the resource") -- eventual-consistency propagation, not a real rejection. Poll
    through it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] != "WAFUnavailableEntityException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
