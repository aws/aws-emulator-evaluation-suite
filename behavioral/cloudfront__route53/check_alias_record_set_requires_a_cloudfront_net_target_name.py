"""alias-record-set-requires-a-cloudfront-net-target-name."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alias-record-set-requires-a-cloudfront-net-target-name"
GROUP = "alias-target"
SERVICES = ["cloudfront", "route53"]

_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"
#: Route 53's fixed hosted zone id for an alias record set that targets a CloudFront
#: distribution (the value every CloudFront customer is told to hard-code).
_CF_ALIAS_HOSTED_ZONE_ID = "Z2FDTNDATAQYW2"
_DEPLOYED_DEADLINE_S = 900


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An alias record set naming Route 53's fixed CloudFront hosted zone id accepts a real
    distribution's domain name as its target, and refuses one that is not a cloudfront.net
    name, even though neither target is checked for existence.

    Reference: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-alias.html
    """
    cf = ctx.client("cloudfront", region="us-east-1")
    r53 = ctx.client("route53")

    tok = ctx.unique_name("sim2real-cfr53-").lower()

    dist_id, dist_domain = _create_distribution(ctx, cf, tok)
    ctx.on_cleanup(lambda: _retire_distribution(cf, dist_id))

    zone_id = r53.create_hosted_zone(
        Name=f"{tok}.test.", CallerReference=ctx.unique_name("sim2real-cfr53-"),
    )["HostedZone"]["Id"]
    # Registered before any record in the zone, so it runs LAST under LIFO: Route 53
    # refuses to delete a hosted zone that still holds a non-NS/SOA record.
    ctx.on_cleanup(lambda: r53.delete_hosted_zone(Id=zone_id))

    good_name = f"cdn.{tok}.test."
    r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [_alias_change("CREATE", good_name, dist_domain)]},
    )
    ctx.on_cleanup(lambda: r53.change_resource_record_sets(
        HostedZoneId=zone_id, ChangeBatch={"Changes": [_alias_change("DELETE", good_name, dist_domain)]},
    ))

    listed = r53.list_resource_record_sets(
        HostedZoneId=zone_id, StartRecordName=good_name, StartRecordType="A", MaxItems="1",
    )["ResourceRecordSets"]
    assert listed and listed[0]["Name"] == good_name, (
        f"expected the alias naming the distribution's own domain to be listed as {good_name!r}, "
        f"got {listed!r}"
    )
    assert listed[0]["AliasTarget"]["DNSName"] == f"{dist_domain}.", (
        f"expected the stored alias target to echo the distribution's domain name with a "
        f"trailing dot, got {listed[0]['AliasTarget']['DNSName']!r}"
    )

    bad_name = f"notcdn.{tok}.test."
    bad_target = f"{ctx.unique_name('sim2real-cfr53-')}.example.com."
    code, message = _refusal(lambda: r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [_alias_change("CREATE", bad_name, bad_target)]},
    ))
    assert code == "InvalidChangeBatch", (
        f"an alias naming the CloudFront hosted zone id but targeting a non-cloudfront.net "
        f"name was expected to be refused as InvalidChangeBatch, got {code!r} / {message!r}"
    )
    expected_message = (
        f"[Tried to create an alias that targets {bad_target}, type A in zone "
        f"{_CF_ALIAS_HOSTED_ZONE_ID}, but the alias target name does not lie within the "
        f"target zone]"
    )
    assert message == expected_message, f"unexpected InvalidChangeBatch message: {message!r}"

    # Change batches are transactional (ChangeResourceRecordSets makes all or none of a
    # batch's changes), so the refused record is never partially created; an independent
    # read confirms it, rather than relying on the exception alone.
    still_absent = r53.list_resource_record_sets(
        HostedZoneId=zone_id, StartRecordName=bad_name, StartRecordType="A", MaxItems="1",
    )["ResourceRecordSets"]
    assert not any(r["Name"] == bad_name for r in still_absent), (
        f"the refused alias was expected to leave no record named {bad_name!r}; "
        f"got {still_absent!r}"
    )


def _alias_change(action: str, name: str, dns_name: str) -> dict:
    return {
        "Action": action,
        "ResourceRecordSet": {
            "Name": name,
            "Type": "A",
            "AliasTarget": {
                "HostedZoneId": _CF_ALIAS_HOSTED_ZONE_ID,
                "DNSName": dns_name,
                "EvaluateTargetHealth": False,
            },
        },
    }


def _refusal(fn) -> tuple[str, str]:
    """Run ``fn``; on a ClientError return its (code, message). Raises on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_distribution(ctx, cf, tok: str) -> tuple[str, str]:
    """A disabled distribution with a placeholder custom origin; only its own DomainName matters."""
    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-cfr53-"),
        "Comment": "sim2real cloudfront alias target fixture",
        "Enabled": False,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "CustomOrigin",
            "DomainName": "origin.example.com",
            "CustomOriginConfig": {
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "https-only",
                "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            },
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "CustomOrigin",
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": _CACHING_OPTIMIZED,
        },
    })["Distribution"]
    return dist["Id"], dist["DomainName"]


def _poll_until(probe, predicate, *, timeout_s, interval_s=10.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last: {last!r})")


def _retire_distribution(cf, dist_id: str) -> None:
    """Disable if enabled, wait for Deployed, delete; a failed delete raises."""
    try:
        resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg, etag = resp["DistributionConfig"], resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    _poll_until(
        lambda: cf.get_distribution(Id=dist_id)["Distribution"]["Status"],
        lambda s: s == "Deployed", timeout_s=_DEPLOYED_DEADLINE_S,
        description=f"distribution {dist_id} reaching Deployed",
    )
    etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
