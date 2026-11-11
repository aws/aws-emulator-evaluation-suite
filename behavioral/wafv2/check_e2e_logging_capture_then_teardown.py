"""e2e-logging-capture-then-teardown."""
from __future__ import annotations

import datetime as dt
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-logging-capture-then-teardown"
GROUP = "e2e"
SERVICES = ["wafv2"]

#: WAFNonexistentItemException's message for a web ACL with no logging configuration.
NONEXISTENT_MESSAGE = (
    "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."
)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With logging enabled on an associated WebACL, GetSampledRequests reports the driven traffic with Action
    COUNT; after DeleteLoggingConfiguration, ListLoggingConfigurations omits the WebACL and
    GetLoggingConfiguration fails with WAFNonexistentItemException and the exact message.
    """
    wafv2 = ctx.client("wafv2")
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    scope = "REGIONAL"

    api = _create_mock_rest_api(ctx)

    web_acl_name = ctx.unique_name("sim2real-behav-e2e-log-")
    metric_name = web_acl_name.replace("-", "")
    rule_metric_name = f"{metric_name}rule"
    web_acl_create = wafv2.create_web_acl(
        Name=web_acl_name,
        Scope=scope,
        DefaultAction={"Allow": {}},
        Rules=[
            {
                "Name": "count-everything",
                "Priority": 0,
                "Action": {"Count": {}},
                "Statement": {
                    "ByteMatchStatement": {
                        "SearchString": b"/",
                        "FieldToMatch": {"UriPath": {}},
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        "PositionalConstraint": "STARTS_WITH",
                    }
                },
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": rule_metric_name,
                },
            }
        ],
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name,
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )
    web_acl_id = web_acl_create["Summary"]["Id"]
    web_acl_arn = web_acl_create["Summary"]["ARN"]

    account_id = sts.get_caller_identity()["Account"]
    log_group_name = f"aws-waf-logs-{ctx.unique_name('sim2real-behav-')}"
    logs.create_log_group(
        logGroupName=log_group_name, tags={"sim2real": CHECK, "sim2real:managed": "true"}
    )
    log_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group_name}"

    def _teardown() -> None:
        try:
            wafv2.disassociate_web_acl(ResourceArn=api["resource_arn"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise
        try:
            wafv2.delete_logging_configuration(ResourceArn=web_acl_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise
        wafv2.delete_web_acl(
            Name=web_acl_name,
            Scope=scope,
            Id=web_acl_id,
            LockToken=wafv2.get_web_acl(Name=web_acl_name, Scope=scope, Id=web_acl_id)["LockToken"],
        )
        logs.delete_log_group(logGroupName=log_group_name)

    ctx.on_cleanup(_teardown)

    wafv2.put_logging_configuration(
        LoggingConfiguration={
            "ResourceArn": web_acl_arn,
            "LogDestinationConfigs": [log_group_arn],
        }
    )
    _retry_unavailable(lambda: wafv2.associate_web_acl(WebACLArn=web_acl_arn, ResourceArn=api["resource_arn"]))

    _poll_until(lambda: _http_status(api["invoke_url"]), lambda s: s == 200, timeout_s=90.0)
    for _ in range(10):
        _http_status(api["invoke_url"])
        time.sleep(1)

    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(hours=3)

    def _sample() -> list:
        # WAF regional enforcement/sampling can lag association propagation by up to a
        # few minutes -- a one-shot burst of traffic sent before polling started may
        # predate when sampling actually turns on, so keep driving fresh traffic on
        # every poll iteration rather than relying on the burst already sent above.
        for _ in range(5):
            _http_status(api["invoke_url"])
        return wafv2.get_sampled_requests(
            WebAclArn=web_acl_arn,
            RuleMetricName=rule_metric_name,
            Scope=scope,
            TimeWindow={"StartTime": start, "EndTime": dt.datetime.now(dt.timezone.utc)},
            MaxItems=100,
        )["SampledRequests"]

    sampled = _poll_until(_sample, lambda s: len(s) > 0, timeout_s=240.0, interval_s=10.0)
    assert sampled[0]["Action"] == "COUNT", (
        f"expected the sampled request to carry the rule's own COUNT action, got {sampled[0].get('Action')!r}"
    )

    wafv2.delete_logging_configuration(ResourceArn=web_acl_arn)

    def _still_listed() -> bool:
        cfgs = wafv2.list_logging_configurations(Scope=scope)["LoggingConfigurations"]
        return any(c["ResourceArn"] == web_acl_arn for c in cfgs)

    still_listed = _poll_until(
        _still_listed, lambda still_listed: not still_listed, timeout_s=30.0, interval_s=2.0
    )
    assert not still_listed, "deleted logging configuration is still in ListLoggingConfigurations"

    code, message = _error(lambda: wafv2.get_logging_configuration(ResourceArn=web_acl_arn))
    assert code == "WAFNonexistentItemException", (
        f"GetLoggingConfiguration should refuse the now-deleted configuration, got {code!r}"
    )
    assert message == NONEXISTENT_MESSAGE, message


def _retry_unavailable(fn, *, timeout_s: float = 180.0, interval_s: float = 10.0):
    """A just-created API Gateway stage can be transiently unresolvable to WAFv2
    (WAFUnavailableEntityException: "AWS WAF couldn't retrieve the resource") -- eventual-
    consistency propagation, not a real rejection. Poll through it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFUnavailableEntityException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _error(fn):
    """Call fn(); return (code, message) of its botocore error. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected GetLoggingConfiguration to fail, but it SUCCEEDED and returned {result!r}")


def _http_status(url: str, timeout: float = 10.0) -> int | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as err:
        return err.code
    except (urllib.error.URLError, ConnectionError, TimeoutError):
        return None


def _poll_until(probe, predicate, timeout_s: float = 90.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _create_mock_rest_api(ctx) -> dict:
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-api-")
    api = apigw.create_rest_api(
        name=name,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(
        r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": ""},
    )
    stage_name = "test"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    invoke_url = f"{ctx.rest_api_url(api_id, stage_name)}/"
    resource_arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}/stages/{stage_name}"
    return {"api_id": api_id, "invoke_url": invoke_url, "resource_arn": resource_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
