"""xsvc-cloudfront-3-access-logs-delivery-source-outside-us-east-1-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "xsvc-cloudfront-3-access-logs-delivery-source-outside-us-east-1-rejected"
GROUP = "region-pinning"
SERVICES = ["cloudfront", "logs"]

#: CloudFront's vended-log control plane is us-east-1 only. This literal names a region-pinned
#: service property, not an account assumption.
_HOME_REGION = "us-east-1"
_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]
_NOT_FOUND = "Requested Delivery Source does not exist in this account."


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; RAISES if fn unexpectedly succeeds."""
    try:
        result = fn()
    except Exception as exc:  # botocore ClientError
        err = getattr(exc, "response", {}).get("Error", {})
        if not err:
            raise
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_source_if_present(logs, name) -> None:
    """Deletes the source a target wrongly created; absence is the expected outcome."""
    try:
        logs.delete_delivery_source(name=name)
    except Exception as exc:  # botocore ClientError
        if getattr(exc, "response", {}).get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _wait_deployed(cf, dist_id, timeout_s) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if cf.get_distribution(Id=dist_id)["Distribution"]["Status"] == "Deployed":
            return True
        time.sleep(2)
    return False


def _delete_distribution_when_deployed(cf, dist_id) -> None:
    """Delete the distribution, bounded to fit the 60 s cleanup budget; the body waits for Deployed."""
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        r = cf.get_distribution(Id=dist_id)
        if r["Distribution"]["Status"] == "Deployed":
            cf.delete_distribution(Id=dist_id, IfMatch=r["ETag"])
            return
        time.sleep(5)
    raise RuntimeError(
        f"cloudfront distribution {dist_id} never reached Deployed; not deleted"
    )


@tags("axis:rejection", "concern:negative-classes", "concern:e2e", "cap:c1", "plane:control")
def run(ctx) -> None:
    """PutDeliverySource for a distribution's ACCESS_LOGS is rejected outside us-east-1 and creates
    nothing there, while the identical call in us-east-1 creates a source for this distribution.
    """
    cf = ctx.client("cloudfront")
    other_region = ctx.region if ctx.region != _HOME_REGION else "us-west-2"
    away = ctx.client("logs", region=other_region)
    home = ctx.client("logs", region=_HOME_REGION)

    dist = cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": {
            "CallerReference": ctx.unique_name("sim2real-xsvc-cflogs-cr-"),
            "Comment": "sim2real vended-log region pinning",
            "Enabled": False,
            "Origins": {"Quantity": 1, "Items": [{
                "Id": "origin", "DomainName": "example.com",
                "CustomOriginConfig": {"HTTPPort": 80, "HTTPSPort": 443,
                                       "OriginProtocolPolicy": "https-only"}}]},
            "DefaultCacheBehavior": {"TargetOriginId": "origin", "ViewerProtocolPolicy": "allow-all",
                                     "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"},
        },
        "Tags": {"Items": _TAG_SET},
    })["Distribution"]
    dist_id, dist_arn = dist["Id"], dist["ARN"]
    ctx.on_cleanup(lambda: _delete_distribution_when_deployed(ctx.client("cloudfront"), dist_id))

    name = ctx.unique_name("sim2real-xsvc-cflogs-src-")
    code, message = _error(lambda: away.put_delivery_source(
        name=name, resourceArn=dist_arn, logType="ACCESS_LOGS"))
    # Registered even though the call was rejected: had the target accepted it, the source exists.
    ctx.on_cleanup(lambda: _delete_source_if_present(ctx.client("logs", region=other_region), name))
    assert code == "ValidationException", (
        f"PutDeliverySource(ACCESS_LOGS) for a CloudFront distribution in {other_region} must be "
        f"rejected with ValidationException, got {code!r}: {message!r}"
    )
    expected = f"PutDeliverySource action is not supported for this LogType in region {other_region}"
    assert message == expected, f"the rejection message is {message!r}, expected {expected!r}"
    absent = _error(lambda: away.get_delivery_source(name=name))
    assert absent == ("ResourceNotFoundException", _NOT_FOUND), (
        f"a rejected PutDeliverySource must create nothing in {other_region}: GetDeliverySource "
        f"returned {absent!r}, expected ResourceNotFoundException {_NOT_FOUND!r}"
    )

    # Positive control: the same request in the home region creates the source.
    src = home.put_delivery_source(name=name, resourceArn=dist_arn, logType="ACCESS_LOGS",
                                   tags={"sim2real": "behavioral"})["deliverySource"]
    ctx.on_cleanup(lambda: ctx.client("logs", region=_HOME_REGION).delete_delivery_source(
        name=name))
    got = home.get_delivery_source(name=name)["deliverySource"]
    assert got["resourceArns"] == [dist_arn], (
        f"the {_HOME_REGION} source must point at this distribution {dist_arn!r}, got {got!r}"
    )
    assert got["service"] == "cloudfront" and got["logType"] == "ACCESS_LOGS", (
        f"the {_HOME_REGION} source must be cloudfront/ACCESS_LOGS, got {got!r}"
    )
    assert src["arn"].split(":")[3] == _HOME_REGION, (
        f"the created source's ARN must be in {_HOME_REGION}, got {src['arn']!r}"
    )
    still_absent = _error(lambda: away.get_delivery_source(name=name))
    assert still_absent == ("ResourceNotFoundException", _NOT_FOUND), (
        f"creating the source in {_HOME_REGION} must not make it visible in {other_region}, got "
        f"{still_absent!r}"
    )

    # The disabled distribution can only be deleted once Deployed, and cleanup is bounded at
    # 60 s, so the wait is part of the body.
    assert _wait_deployed(cf, dist_id, 1200), f"distribution {dist_id} never reached Deployed"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
