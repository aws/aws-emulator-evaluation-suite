"""e2e-logging-configuration-lifecycle-with-traffic."""
from __future__ import annotations

import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-logging-configuration-lifecycle-with-traffic"
GROUP = "e2e"
SERVICES = ["wafv2"]

#: WAFNonexistentItemException's message for a web ACL with no logging configuration.
NONEXISTENT_MESSAGE = (
    "AWS WAF couldn’t perform the operation because your resource doesn’t exist."
)


@tags("axis:happy-path", "cap:c2", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """PutLoggingConfiguration on an associated WebACL is returned by Get and List with the log group, the matching path
    answers 403 and another 200 with BLOCK samples, and after deletion the configuration is gone from List and Get
    fails with WAFNonexistentItemException and the exact message.
    """
    wafv2 = ctx.client("wafv2")
    teardown_deadline: dict = {}
    logs = ctx.client("logs")
    api = _create_mock_rest_api(ctx, ["blocked", "ok"])

    webacl_name = ctx.unique_name("sim2real-wafv2-webacl-")
    block_metric = "BlockPathRuleMetric"
    webacl = wafv2.create_web_acl(
        Name=webacl_name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        Rules=[
            {
                "Name": "BlockPathRule",
                "Priority": 0,
                "Action": {"Block": {}},
                "Statement": {
                    "ByteMatchStatement": {
                        "SearchString": "blocked",
                        "FieldToMatch": {"UriPath": {}},
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        "PositionalConstraint": "CONTAINS",
                    }
                },
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": block_metric,
                },
            }
        ],
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": webacl_name,
        },
    )["Summary"]
    webacl_id = webacl["Id"]
    webacl_arn = webacl["ARN"]
    ctx.on_cleanup(
        lambda: _delete_when_unreferenced(
            teardown_deadline,
            lambda: wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id)["LockToken"],
            lambda token: wafv2.delete_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id, LockToken=token),
        )
    )

    # A freshly-created API Gateway stage can take a short while to become resolvable
    # to WAF (WAFUnavailableEntityException: "AWS WAF couldn't retrieve the
    # resource") -- poll through that propagation window.
    _retry_unavailable(lambda: wafv2.associate_web_acl(WebACLArn=webacl_arn, ResourceArn=api["stage_arn"]))
    ctx.on_cleanup(lambda: _safe(lambda: wafv2.disassociate_web_acl(ResourceArn=api["stage_arn"])))

    # WAF requires CloudWatch Logs log group destinations to be named with the
    # "aws-waf-logs-" prefix (see the AWS WAF logging developer guide).
    log_group_name = f"aws-waf-logs-{ctx.unique_name('sim2real-wafv2-')}"
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_log_group(logGroupName=log_group_name)))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]
    if log_group_arn.endswith(":*"):
        log_group_arn = log_group_arn[:-2]

    put_result = wafv2.put_logging_configuration(
        LoggingConfiguration={"ResourceArn": webacl_arn, "LogDestinationConfigs": [log_group_arn]}
    )["LoggingConfiguration"]
    assert put_result["ResourceArn"] == webacl_arn, (
        f"PutLoggingConfiguration echoed ResourceArn={put_result['ResourceArn']!r}, expected {webacl_arn!r}"
    )
    assert put_result["LogDestinationConfigs"] == [log_group_arn], (
        f"PutLoggingConfiguration echoed destinations {put_result['LogDestinationConfigs']!r}, "
        f"expected [{log_group_arn!r}]"
    )
    ctx.on_cleanup(lambda: _safe(lambda: wafv2.delete_logging_configuration(ResourceArn=webacl_arn)))

    got = wafv2.get_logging_configuration(ResourceArn=webacl_arn)["LoggingConfiguration"]
    assert got["LogDestinationConfigs"] == [log_group_arn], (
        f"GetLoggingConfiguration (independent read) returned destinations "
        f"{got['LogDestinationConfigs']!r}, expected [{log_group_arn!r}]"
    )

    listed = wafv2.list_logging_configurations(Scope="REGIONAL")["LoggingConfigurations"]
    assert any(lc["ResourceArn"] == webacl_arn for lc in listed), (
        f"{webacl_arn} missing from ListLoggingConfigurations after PutLoggingConfiguration succeeded"
    )

    # Generate real traffic through the still-associated, still-logging WebACL.
    blocked_status = _poll_until(
        lambda: _http_get(api["invoke_url"] + "/blocked"),
        lambda status: status == 403,
        timeout_s=150.0,
        interval_s=5.0,
        reason="WAF rule association can lag propagation, so the block may not take effect immediately",
    )
    assert blocked_status == 403, f"expected the BlockPathRule to return 403, got {blocked_status!r}"
    ok_status = _http_get(api["invoke_url"] + "/ok")
    assert ok_status == 200, f"expected the unmatched path to pass through as 200, got {ok_status!r}"

    # GetSampledRequests returns a statistical SAMPLE, not a guaranteed log of every
    # matched request -- a single blocked call may not be captured. Generate a burst
    # of additional blocked requests to raise the odds of a sample landing, then poll
    # with a generous timeout for the sample to become queryable.
    for _ in range(25):
        _http_get(api["invoke_url"] + "/blocked")

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=2)
    samples = _poll_until(
        lambda: wafv2.get_sampled_requests(
            WebAclArn=webacl_arn,
            RuleMetricName=block_metric,
            Scope="REGIONAL",
            TimeWindow={"StartTime": start, "EndTime": end},
            MaxItems=500,
        )["SampledRequests"],
        lambda samples: len(samples) > 0,
        timeout_s=240.0,
        interval_s=15.0,
        reason="GetSampledRequests is a statistical sample, not a guaranteed log of every matched request",
    )
    assert samples, "traffic was not sampled while logging was enabled"
    assert samples[0]["Action"] == "BLOCK", (
        f"sampled request action was {samples[0]['Action']!r}, expected BLOCK for the matched rule"
    )

    # Delete the logging configuration and confirm it is fully gone.
    wafv2.delete_logging_configuration(ResourceArn=webacl_arn)
    listed_after = wafv2.list_logging_configurations(Scope="REGIONAL")["LoggingConfigurations"]
    assert not any(lc["ResourceArn"] == webacl_arn for lc in listed_after), (
        f"{webacl_arn} still present in ListLoggingConfigurations after DeleteLoggingConfiguration"
    )
    code, message = _error(lambda: wafv2.get_logging_configuration(ResourceArn=webacl_arn))
    assert code == "WAFNonexistentItemException", (
        f"GetLoggingConfiguration after delete returned code={code!r}, expected WAFNonexistentItemException"
    )
    assert message == NONEXISTENT_MESSAGE, message


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
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "WAFNonexistentItemException",
        ):
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
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-wafv2-api-"), tags={"sim2real": CHECK})
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, reason=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    detail = f" ({reason})" if reason else ""
    raise AssertionError(f"condition not met within {timeout_s}s{detail}; last observed: {last!r}")


def _retry_unavailable(fn, *, timeout_s=180.0, interval_s=10.0):
    """A just-created resource can be transiently unresolvable to a dependent WAFv2
    call (WAFUnavailableEntityException: "AWS WAF couldn't retrieve the resource") --
    eventual-consistency propagation, not a real rejection. Poll through it."""
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
