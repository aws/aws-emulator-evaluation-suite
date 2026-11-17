"""apex-alias-hosted-zone-id-must-match-the-aliased-s3-website-endpoint."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apex-alias-hosted-zone-id-must-match-the-aliased-s3-website-endpoint"
GROUP = "s3-website-alias"
SERVICES = ["route53", "s3"]

# Both AWS-owned per-Region constants (the S3 static-website endpoint and the Route 53 hosted
# zone ID an Alias target uses to reach it): https://docs.aws.amazon.com/general/latest/gr/s3.html
_S3_WEBSITE_ENDPOINT = {
    "us-west-2": "s3-website-us-west-2.amazonaws.com",
    "us-east-1": "s3-website-us-east-1.amazonaws.com",
}
_S3_WEBSITE_HOSTED_ZONE_ID = {
    "us-west-2": "Z3BJ6K6RIION7M",
    "us-east-1": "Z3AQBSTGFYJSTF",
}

_INSYNC_DEADLINE_S = 120.0


def _caller_reference() -> str:
    return f"sim2real-cr-{secrets.token_hex(12)}"


def _code_of(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code") or ""


def _wait_insync(r53, change_id: str) -> None:
    deadline = time.monotonic() + _INSYNC_DEADLINE_S
    while True:
        status = r53.get_change(Id=change_id)["ChangeInfo"]["Status"]
        if status == "INSYNC":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"change {change_id!r} still {status!r} after {_INSYNC_DEADLINE_S}s"
            )
        time.sleep(2.0)


def _alias_change(r53, zone_id: str, name: str, website_host: str, alias_zone_id: str):
    return r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [{
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": name,
                "Type": "A",
                "AliasTarget": {
                    "HostedZoneId": alias_zone_id,
                    "DNSName": website_host,
                    "EvaluateTargetHealth": False,
                },
            },
        }]},
    )


def _non_apex_records(r53, zone_id: str) -> list:
    out = []
    kwargs = {"HostedZoneId": zone_id}
    while True:
        resp = r53.list_resource_record_sets(**kwargs)
        out.extend(r for r in resp["ResourceRecordSets"] if r["Type"] not in ("NS", "SOA"))
        if not resp.get("IsTruncated"):
            return out
        kwargs["StartRecordName"] = resp["NextRecordName"]
        kwargs["StartRecordType"] = resp["NextRecordType"]


def _empty_and_delete_zone(r53, zone_id: str) -> None:
    leftovers = _non_apex_records(r53, zone_id)
    if leftovers:
        r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={"Changes": [
                {"Action": "DELETE", "ResourceRecordSet": r} for r in leftovers
            ]},
        )
    try:
        r53.delete_hosted_zone(Id=zone_id)
    except ClientError as exc:
        if _code_of(exc) != "NoSuchHostedZone":
            raise


def _expect_error(call):
    """Call `call`, require a ClientError, and return (code, message).

    Raises on an unexpected SUCCESS rather than a falsy sentinel, so an over-permissive target
    cannot be mistaken for a mere code mismatch.
    """
    try:
        result = call()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the change to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An Alias target naming a real S3 website endpoint is refused when its HostedZoneId is for
    a different Region's website endpoint, and accepted once the two agree.
    """
    region = ctx.region
    other_region = next(r for r in _S3_WEBSITE_ENDPOINT if r != region)
    website_host = _S3_WEBSITE_ENDPOINT[region]
    correct_zone_id = _S3_WEBSITE_HOSTED_ZONE_ID[region]
    wrong_zone_id = _S3_WEBSITE_HOSTED_ZONE_ID[other_region]

    r53 = ctx.client("route53")
    s3 = ctx.client("s3")

    zone_label = ctx.unique_name("sim2real-behav-aliaszone").lower().replace("_", "-")
    zone_name = f"{zone_label}.example.test."
    bucket = zone_name.rstrip(".")
    assert len(bucket) <= 63, f"bucket name {bucket!r} ({len(bucket)} chars) exceeds 63"

    zone_resp = r53.create_hosted_zone(Name=zone_name, CallerReference=_caller_reference())
    zone_id = zone_resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: _empty_and_delete_zone(r53, zone_id))

    create_bucket_kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        create_bucket_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**create_bucket_kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_website(
        Bucket=bucket, WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}}
    )

    # ---- the refusal: the right website host, the WRONG region's hosted zone ID -------------
    code, message = _expect_error(
        lambda: _alias_change(r53, zone_id, zone_name, website_host, wrong_zone_id)
    )
    assert code == "InvalidChangeBatch", (
        f"an alias whose HostedZoneId does not match its DNSName's own service zone must be "
        f"refused with InvalidChangeBatch, got {code!r}: {message!r}"
    )
    assert message == (
        f"[Tried to create an alias that targets {website_host}., type A in zone "
        f"{wrong_zone_id}, but the alias target name does not lie within the target zone]"
    ), f"the refusal must name the exact host and the wrong zone id used, got {message!r}"

    # ---- effect absent: the zone still has only its default NS/SOA records -------------------
    after_refusal = _non_apex_records(r53, zone_id)
    assert after_refusal == [], (
        f"the refused change must not have created any record: {after_refusal!r}"
    )

    # ---- positive control: the SAME alias, with the matching hosted zone ID, succeeds --------
    change_id = _alias_change(r53, zone_id, zone_name, website_host, correct_zone_id)[
        "ChangeInfo"
    ]["Id"]
    _wait_insync(r53, change_id)

    stored = [
        r for r in _non_apex_records(r53, zone_id)
        if r["Name"].rstrip(".").lower() == zone_name.rstrip(".").lower() and r["Type"] == "A"
    ]
    assert len(stored) == 1, f"ListResourceRecordSets must show exactly one apex A alias: {stored!r}"
    alias_target = stored[0]["AliasTarget"]
    assert alias_target["HostedZoneId"] == correct_zone_id, (
        f"the accepted alias must store the matching hosted zone ID {correct_zone_id!r}, got "
        f"{alias_target['HostedZoneId']!r}"
    )
    assert alias_target["DNSName"].rstrip(".").lower() == website_host.lower(), (
        f"the accepted alias must still name {website_host!r}, got {alias_target['DNSName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
