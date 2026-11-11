"""obs-cloudfront-3-delivery-source-unsupported-log-type-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "obs-cloudfront-3-delivery-source-unsupported-log-type-rejected"
GROUP = "log-delivery"
SERVICES = ["cloudfront", "logs"]

# The model allows any PutDeliverySource `logType` matching ^[\w]*$ (length 1..255), but for a
# CloudFront distribution ARN the service accepts only the log types CloudFront vends
# (DescribeConfigurationTemplates lists only ACCESS_LOGS); a service rule narrower than the model.

#: The vended-log delivery plane for CloudFront exists only in us-east-1 (PutDeliverySource in
#: us-west-2 is ValidationException "not supported for this LogType in region us-west-2").
DELIVERY_REGION = "us-east-1"

#: Model-valid (matches ^[\w]*$) but not a log type CloudFront vends.
UNSUPPORTED_LOG_TYPE = "ERROR_LOGS"

_TAGS = {"sim2real": "obs-cloudfront-3"}


def _poll_until(probe, predicate, *, timeout_s, interval_s=10.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description} (last: {last!r})")


def _error(fn):
    """(code, message) of the AWS error `fn` raised. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 — botocore ClientError carries .response
        resp = getattr(exc, "response", None)
        if not resp:
            raise
        return resp["Error"]["Code"], resp["Error"].get("Message", "")
    raise AssertionError(f"expected the call to fail, but it succeeded: {result!r}")


def _wait_deployed(cf, dist_id, timeout_s=1500.0) -> str:
    holder = {}

    def probe():
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=15.0,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _code(exc) -> str:
    return ((getattr(exc, "response", None) or {}).get("Error") or {}).get("Code", "")


def _teardown_distributions(cf, dist_ids, timeout_s=1500.0) -> None:
    """Disable, wait for Deployed, delete; called from the check body on the success path.

    ctx cleanups are bounded at 60 s, far below one CloudFront disable->Deployed cycle."""
    for dist_id in dist_ids:
        resp = cf.get_distribution_config(Id=dist_id)
        cfg = resp["DistributionConfig"]
        if cfg["Enabled"]:
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, IfMatch=resp["ETag"], DistributionConfig=cfg)
    for dist_id in dist_ids:
        cf.delete_distribution(Id=dist_id, IfMatch=_wait_deployed(cf, dist_id, timeout_s))


def _release_distribution(cf, dist_id) -> None:
    """Failure-path net, a few calls only: delete if already disabled and Deployed, else disable
    and report."""
    try:
        resp = cf.get_distribution_config(Id=dist_id)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "NoSuchDistribution":
            raise RuntimeError(f"cloudfront distribution {dist_id}: {exc!r}") from exc
        return
    try:
        cfg = resp["DistributionConfig"]
        if cfg["Enabled"]:
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, IfMatch=resp["ETag"], DistributionConfig=cfg)
            raise RuntimeError(
                f"cloudfront distribution {dist_id}: disabled by cleanup, delete pending"
            )
        cur = cf.get_distribution(Id=dist_id)
        if cur["Distribution"]["Status"] != "Deployed":
            raise RuntimeError(
                f"cloudfront distribution {dist_id}: disabled, still deploying, delete pending"
            )
        cf.delete_distribution(Id=dist_id, IfMatch=cur["ETag"])
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchDistribution",):
            raise RuntimeError(f"cloudfront distribution {dist_id}: {exc!r}") from exc


def _delete_source_if_present(logs, name) -> None:
    try:
        logs.delete_delivery_source(name=name)
    except Exception as exc:  # noqa: BLE001
        code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code")
        if code != "ResourceNotFoundException":
            raise RuntimeError(f"logs delivery source {name}: {exc!r}") from exc


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """PutDeliverySource with a model-valid logType CloudFront does not vend is rejected, creates
    nothing, and the same distribution ARN with logType ACCESS_LOGS is accepted.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutDeliverySource.html
    """
    cf = ctx.client("cloudfront")
    logs = ctx.client("logs", region=DELIVERY_REGION)

    # A disabled distribution is a real CloudFront resource and never serves traffic; nothing here
    # needs it Deployed until teardown.
    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-obs3-lt-"),
        "Comment": "sim2real obs-cloudfront-3 delivery-source log-type rejection",
        "Enabled": False,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "origin", "DomainName": f"{ctx.unique_name('sim2real-obs3-lt-')}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
        }]},
        "DefaultCacheBehavior": {"TargetOriginId": "origin", "ViewerProtocolPolicy": "allow-all",
                                 "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6"},
    })["Distribution"]
    dist_id, dist_arn = dist["Id"], dist["ARN"]
    ctx.on_cleanup(lambda: _release_distribution(cf, dist_id))
    cf.tag_resource(Resource=dist_arn, Tags={"Items": [{"Key": k, "Value": v} for k, v in _TAGS.items()]})

    # --- the break: one thing wrong, the log type --------------------------------------------------
    bad_name = ctx.unique_name("sim2real-obs3-lt-bad-")
    ctx.on_cleanup(lambda: _delete_source_if_present(logs, bad_name))  # if a target wrongly accepts
    code, message = _error(lambda: logs.put_delivery_source(
        name=bad_name, resourceArn=dist_arn, logType=UNSUPPORTED_LOG_TYPE, tags=_TAGS))
    assert code == "ValidationException", (
        f"PutDeliverySource(logType={UNSUPPORTED_LOG_TYPE!r}) on a CloudFront distribution must be "
        f"ValidationException, got {code!r}: {message!r}")
    assert message == "This service is not allowed for this LogSource.", (
        f"the rejection must name the log-type/service mismatch, got {message!r}")
    absent_code, _ = _error(lambda: logs.get_delivery_source(name=bad_name))
    assert absent_code == "ResourceNotFoundException", (
        f"a rejected PutDeliverySource must create nothing: GetDeliverySource({bad_name!r}) returned "
        f"{absent_code!r}, expected ResourceNotFoundException")

    # --- positive control: same ARN, the log type CloudFront does vend -----------------------------
    good_name = ctx.unique_name("sim2real-obs3-lt-ok-")
    src = logs.put_delivery_source(name=good_name, resourceArn=dist_arn, logType="ACCESS_LOGS",
                                   tags=_TAGS)["deliverySource"]
    ctx.on_cleanup(lambda: _delete_source_if_present(logs, good_name))
    assert (src["service"], src["logType"], src["resourceArns"]) == ("cloudfront", "ACCESS_LOGS", [dist_arn]), (
        f"the accepted source must be a cloudfront ACCESS_LOGS source for {dist_arn}, got {src!r}")
    read = logs.get_delivery_source(name=good_name)["deliverySource"]
    assert read["logType"] == "ACCESS_LOGS" and read["resourceArns"] == [dist_arn], (
        f"GetDeliverySource must read back what PutDeliverySource stored, got {read!r}")

    vended, token = set(), None
    while True:
        page = logs.describe_configuration_templates(
            service="cloudfront", **({"nextToken": token} if token else {}))
        vended |= {t["logType"] for t in page["configurationTemplates"]}
        token = page.get("nextToken")
        if not token:
            break
    assert "ACCESS_LOGS" in vended and UNSUPPORTED_LOG_TYPE not in vended, (
        f"DescribeConfigurationTemplates(service=cloudfront) must list ACCESS_LOGS and not "
        f"{UNSUPPORTED_LOG_TYPE}, got {sorted(vended)}")

    # The slow distribution teardown runs in the body (see _teardown_distributions).
    logs.delete_delivery_source(name=good_name)
    _teardown_distributions(cf, [dist_id])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
