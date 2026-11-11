"""e2e-logging-configuration-capture-flow."""
from __future__ import annotations

import datetime
import gzip
import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-logging-configuration-capture-flow"
GROUP = "e2e"
SERVICES = ["wafv2"]

#: WAFNonexistentItemException's message for a web ACL with no logging configuration.
NONEXISTENT_MESSAGE = (
    "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."
)

_SAMPLE_HEADER = "x-simparity-sample"
_SAMPLE_VALUE = "sample-me"


@tags("axis:happy-path", "cap:c2", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """PutLoggingConfiguration's S3 destination round-trips through GetLoggingConfiguration, traffic
    through an associated API Gateway stage is sampled AND delivered as a WAF log record to S3,
    and DeleteLoggingConfiguration makes GetLoggingConfiguration fail with WAFNonexistentItem."""
    wafv2 = ctx.client("wafv2")
    s3 = ctx.client("s3")
    apigw = ctx.client("apigateway")

    stage = _create_apigw_stage(ctx, apigw)

    bucket_name = ctx.unique_name("aws-waf-logs-sim2real-").lower().replace("_", "-")
    _create_log_bucket(ctx, s3, bucket_name)
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    webacl_name = ctx.unique_name("sim2real-waf-logcfg-")
    webacl = wafv2.create_web_acl(
        Name=webacl_name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": webacl_name,
        },
        Rules=[
            {
                "Name": "CatchAllCount",
                "Priority": 0,
                "Action": {"Count": {}},
                "Statement": {
                    "ByteMatchStatement": {
                        "SearchString": _SAMPLE_VALUE,
                        "FieldToMatch": {"SingleHeader": {"Name": _SAMPLE_HEADER}},
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        "PositionalConstraint": "EXACTLY",
                    }
                },
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "CatchAllCountMetric",
                },
            }
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )
    webacl_id = webacl["Summary"]["Id"]
    webacl_arn = webacl["Summary"]["ARN"]
    ctx.on_cleanup(lambda: _safe_delete_web_acl(wafv2, webacl_name, "REGIONAL", webacl_id))

    _retry_on_unavailable(ctx, lambda: wafv2.associate_web_acl(WebACLArn=webacl_arn, ResourceArn=stage["stage_arn"]))
    ctx.on_cleanup(lambda: _safe_disassociate(wafv2, stage["stage_arn"]))

    put_resp = wafv2.put_logging_configuration(
        LoggingConfiguration={"ResourceArn": webacl_arn, "LogDestinationConfigs": [bucket_arn]}
    )
    ctx.on_cleanup(lambda: _safe_delete_logging_config(wafv2, webacl_arn))
    assert put_resp["LoggingConfiguration"]["LogDestinationConfigs"] == [bucket_arn], (
        f"PutLoggingConfiguration did not echo the configured destination: "
        f"{put_resp['LoggingConfiguration']['LogDestinationConfigs']!r} != {[bucket_arn]!r}"
    )

    fetched_cfg = wafv2.get_logging_configuration(ResourceArn=webacl_arn)
    assert fetched_cfg["LoggingConfiguration"]["LogDestinationConfigs"] == [bucket_arn], (
        f"GetLoggingConfiguration does not round-trip the destination: "
        f"{fetched_cfg['LoggingConfiguration']['LogDestinationConfigs']!r} != {[bucket_arn]!r}"
    )

    for _ in range(10):
        _http_get(stage["invoke_url"], {_SAMPLE_HEADER: _SAMPLE_VALUE})
        time.sleep(0.2)

    window_end = lambda: datetime.datetime.now(datetime.timezone.utc)
    window_start = window_end() - datetime.timedelta(minutes=15)
    samples = _poll_for_samples(
        ctx,
        wafv2,
        webacl_arn,
        "CatchAllCountMetric",
        window_start,
        window_end,
        stage["invoke_url"],
        timeout_s=240,
        interval_s=2,
    )
    assert len(samples) > 0, "GetSampledRequests returned no samples for the matching rule"
    assert samples[0]["Action"] == "COUNT", f"unexpected sampled action: {samples[0]['Action']!r}"

    # Sampling depends only on the rule's VisibilityConfig, not on logging; only the S3 record
    # proves the configured destination is real.
    records = _poll_for_s3_log_records(
        ctx, s3, bucket_name, stage["invoke_url"], _SAMPLE_HEADER, _SAMPLE_VALUE, timeout_s=480, interval_s=2
    )
    record = records[0]
    matched_rules = [
        r for r in record.get("nonTerminatingMatchingRules", []) if r.get("ruleId") == "CatchAllCount"
    ]
    assert matched_rules, (
        f"the WAF log record delivered to s3://{bucket_name} does not list CatchAllCount among "
        f"nonTerminatingMatchingRules -- the configured destination is not receiving records for "
        f"this rule's decisions: {record!r}"
    )
    assert matched_rules[0].get("action") == "COUNT", (
        f"the delivered log record's matched-rule action is not COUNT: {matched_rules[0]!r}"
    )

    wafv2.delete_logging_configuration(ResourceArn=webacl_arn)
    code, message = _error(lambda: wafv2.get_logging_configuration(ResourceArn=webacl_arn))
    assert code == "WAFNonexistentItemException", (
        f"GetLoggingConfiguration did not 404 with WAFNonexistentItemException after delete: {code!r}"
    )
    assert message == NONEXISTENT_MESSAGE, message



def _create_apigw_stage(ctx, apigw):
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-wafapi-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
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
    stage_name = "prod"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    region = ctx.region
    return {
        "api_id": api_id,
        "stage_arn": f"arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{stage_name}",
        "invoke_url": f"{ctx.rest_api_url(api_id, stage_name)}/",
    }


def _create_log_bucket(ctx, s3, bucket_name):
    kwargs = {"Bucket": bucket_name}
    # CreateBucket rejects a LocationConstraint that names us-east-1 explicitly.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]},
    )


def _empty_and_delete_bucket(s3, bucket_name):
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _http_get(url, headers=None):
    try:
        urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=10).read()
    except (urllib.error.HTTPError, urllib.error.URLError):
        pass


def _error(fn):
    """Call fn(); return (code, message) of its botocore error. A call that succeeds raises
    AssertionError: the caller expects a refusal."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _safe_disassociate(wafv2, resource_arn):
    try:
        wafv2.disassociate_web_acl(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


def _safe_delete_web_acl(wafv2, name, scope, id_):
    try:
        current = wafv2.get_web_acl(Name=name, Scope=scope, Id=id_)
        wafv2.delete_web_acl(Name=name, Scope=scope, Id=id_, LockToken=current["LockToken"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


def _safe_delete_ip_set(wafv2, name, scope, id_):
    try:
        current = wafv2.get_ip_set(Name=name, Scope=scope, Id=id_)
        wafv2.delete_ip_set(Name=name, Scope=scope, Id=id_, LockToken=current["LockToken"])
    except Exception:
        pass


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _retry_on_unavailable(ctx, fn, timeout_s=240, interval_s=2):
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "WAFUnavailableEntityException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    if last_exc is None:
        return fn()
    if _budget_spent(ctx):
        raise TimeoutError("the WAF entity becoming available: the run budget ended first; not graded") from last_exc
    raise last_exc


def _safe_delete_logging_config(wafv2, resource_arn):
    try:
        wafv2.delete_logging_configuration(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


def _poll_for_samples(ctx, wafv2, webacl_arn, metric_name, start, end_fn, invoke_url, timeout_s, interval_s):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last_count = 0
    while time.monotonic() < deadline:
        # Fresh traffic each iteration: sampling can lag association propagation by minutes.
        for _ in range(5):
            _http_get(invoke_url, {_SAMPLE_HEADER: _SAMPLE_VALUE})
        resp = wafv2.get_sampled_requests(
            WebAclArn=webacl_arn,
            RuleMetricName=metric_name,
            Scope="REGIONAL",
            TimeWindow={"StartTime": start, "EndTime": end_fn()},
            MaxItems=100,
        )
        samples = resp.get("SampledRequests", [])
        last_count = len(samples)
        if samples:
            return samples
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError("sampled requests appearing: the run budget ended first; not graded")
    raise AssertionError(f"no sampled requests observed after {timeout_s:.0f}s (last count={last_count})")


def _poll_for_s3_log_records(ctx, s3, bucket_name, invoke_url, header_name, header_value, timeout_s, interval_s):
    """Poll S3 for a delivered WAF log record carrying header_value, sending fresh traffic each round.

    WAF log delivery to S3 is asynchronous (often over a minute) and batched into gzip objects.
    """
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    seen_keys = set()
    while True:
        for _ in range(5):
            _http_get(invoke_url, {header_name: header_value})
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                body = s3.get_object(Bucket=bucket_name, Key=key)["Body"].read()
                try:
                    text = gzip.decompress(body).decode("utf-8")
                except OSError:
                    text = body.decode("utf-8")
                matched = []
                for line in text.splitlines():
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    headers = record.get("httpRequest", {}).get("headers", [])
                    if any(
                        h.get("name", "").lower() == header_name.lower() and h.get("value") == header_value
                        for h in headers
                    ):
                        matched.append(record)
                if matched:
                    return matched
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("a WAF log record arriving in S3: the run budget ended first; not graded")
            raise AssertionError(
                f"no WAF log record naming header {header_name}={header_value!r} arrived in "
                f"s3://{bucket_name} within {timeout_s:.0f}s ({len(seen_keys)} objects inspected)"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
