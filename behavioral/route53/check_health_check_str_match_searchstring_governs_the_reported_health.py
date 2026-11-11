"""health-check-str-match-searchstring-governs-the-reported-health."""

from __future__ import annotations

import ipaddress
import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "health-check-str-match-searchstring-governs-the-reported-health"
GROUP = "health-check"
SERVICES = ["route53"]

_SUBJECT = "route53-searchstring"

_MANAGED_TAGS = [{"Key": "sim2real", "Value": _SUBJECT},
                 {"Key": "sim2real:managed", "Value": "true"},
                 {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


def _code_of(exc):
    return exc.response.get("Error", {}).get("Code") or ""


def _poll(probe, done, *, timeout_s, interval_s=2.0, what="condition"):
    """Poll an observable condition to a bounded deadline; raise on timeout.

    Raises rather than returning the last value so a truncated wait is never read as a result.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last={last!r}"
            )
        time.sleep(interval_s)


def _caller_reference():
    return f"cr-{secrets.token_hex(16)}"

# The monitored endpoint is an S3 static website on port 80: Route 53 checkers reach it without
# SNI. Its bucket policy admits only the CIDRs GetCheckerIpRanges publishes, so it is not public.

_INDEX_KEY = "index.html"


def _bucket_policy(name, checker_cidrs):
    """Read access to the website's objects for the Route 53 health checker addresses only."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{name}/*",
            "Condition": {"IpAddress": {"aws:SourceIp": checker_cidrs}},
        }],
    })


def _delete_bucket(s3, name):
    try:
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if _code_of(exc) != "NoSuchBucket":
            raise


def _create_website(ctx, s3, r53, body):
    """An S3 static website serving `body` at `/` to the health checkers. Returns (bucket, host)."""
    name = ctx.unique_name("sim2real-behav-r53str-")
    kwargs = {"Bucket": name}
    # CreateBucket rejects a LocationConstraint of us-east-1 (InvalidLocationConstraint).
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _MANAGED_TAGS})
    checker_cidrs = r53.get_checker_ip_ranges()["CheckerIpRanges"]
    s3.put_bucket_policy(Bucket=name, Policy=_bucket_policy(name, checker_cidrs))
    s3.put_bucket_website(
        Bucket=name, WebsiteConfiguration={"IndexDocument": {"Suffix": _INDEX_KEY}})
    _put_body(s3, name, body)
    host = f"{name}.s3-website-{ctx.region}.amazonaws.com"
    return name, host


def _put_body(s3, bucket, body):
    s3.put_object(Bucket=bucket, Key=_INDEX_KEY, Body=body.encode(), ContentType="text/plain")


def _served_body(s3, bucket):
    """The body the website currently serves at `/`.

    S3 is strongly read-after-write consistent, so this reflects the latest PutObject.
    """
    return s3.get_object(Bucket=bucket, Key=_INDEX_KEY)["Body"].read().decode()


def _observations(r53, hc_id):
    """(observations, per-checker StatusReport strings) for the health check.

    GetHealthCheckStatus reports one observation PER Route 53 health checker rather than one
    aggregate boolean, so "is it healthy" only exists as a set of per-checker report strings.
    """
    obs = r53.get_health_check_status(HealthCheckId=hc_id)["HealthCheckObservations"]
    return obs, [(entry.get("StatusReport") or {}).get("Status") or "" for entry in obs]


def _await_visible(r53, hc_id, *, timeout_s=90.0):
    """Wait for a just-created health check to become visible to GetHealthCheckStatus.

    It raises NoSuchHealthCheck for a short window after CreateHealthCheck; retry only that.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            r53.get_health_check_status(HealthCheckId=hc_id)
            return
        except ClientError as exc:
            if _code_of(exc) != "NoSuchHealthCheck" or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


def _await_all(r53, hc_id, predicate, what, *, timeout_s=240.0):
    """Wait until every checker's report satisfies `predicate`, with at least one report.

    Requires a non-empty list because all([]) is vacuously true.
    """
    return _poll(
        lambda: _observations(r53, hc_id),
        lambda pair: bool(pair[0]) and all(predicate(s) for s in pair[1]),
        timeout_s=timeout_s, interval_s=5.0, what=what,
    )


def _create_str_match_check(ctx, r53, host, search_string):
    resp = r53.create_health_check(
        CallerReference=_caller_reference(),
        HealthCheckConfig={
            "Type": "HTTP_STR_MATCH",
            "FullyQualifiedDomainName": host,
            "Port": 80,
            "ResourcePath": "/",
            "SearchString": search_string,
            "RequestInterval": 10,
            "FailureThreshold": 1,
            "MeasureLatency": False,
            "Inverted": False,
        },
    )
    hc_id = resp["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda h=hc_id: _delete_health_check(r53, h))
    _tag_health_check(r53, hc_id)
    return hc_id, resp["HealthCheck"]


def _delete_health_check(r53, hc_id):
    try:
        r53.delete_health_check(HealthCheckId=hc_id)
    except ClientError as exc:
        if _code_of(exc) != "NoSuchHealthCheck":
            raise


def _tag_health_check(r53, hc_id):
    r53.change_tags_for_resource(
        ResourceType="healthcheck", ResourceId=hc_id,
        AddTags=[{"Key": "Name", "Value": "sim2real-behav-" + _SUBJECT}] + _MANAGED_TAGS,
    )


_MARKER = "sim2real-behav-route53-searchstring-ok"
_WITHOUT = "sim2real-behav-route53-this-body-omits-the-search-string"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """HTTP_STR_MATCH checkers report Success only while the served body contains SearchString:
    rewriting only the body flips every checker to a string-match Failure and back with the health
    check unchanged, and observations come from published checker IPs in at least three regions.
    """
    s3 = ctx.client("s3")
    r53 = ctx.client("route53")
    bucket, host = _create_website(ctx, s3, r53, _MARKER)

    # --- the endpoint really serves the string, read at the destination S3 will answer from. ---
    body = _served_body(s3, bucket)
    assert _MARKER in body, (
        f"the monitored endpoint must serve a body containing {_MARKER!r} before the health check "
        f"is created, got {body!r}"
    )

    hc_id, hc = _create_str_match_check(ctx, r53, host, _MARKER)
    _await_visible(r53, hc_id)
    baseline_version = hc["HealthCheckVersion"]
    assert hc["HealthCheckConfig"]["SearchString"] == _MARKER, (
        f"CreateHealthCheck must store the SearchString verbatim, got "
        f"{hc['HealthCheckConfig'].get('SearchString')!r} for {_MARKER!r}"
    )

    healthy, healthy_reports = _await_all(
        r53, hc_id, lambda s: s.startswith("Success"),
        f"every Route 53 checker to report Success for {host} while its body contains {_MARKER!r}",
    )

    # --- the checkers are real, distributed and published. ---
    cidrs = [
        ipaddress.ip_network(cidr)
        for cidr in r53.get_checker_ip_ranges()["CheckerIpRanges"]
    ]
    assert cidrs, "GetCheckerIpRanges must publish the ranges the checkers actually come from"
    for entry in healthy:
        addr = ipaddress.ip_address(entry["IPAddress"])
        assert any(addr in net for net in cidrs), (
            f"the checker at {entry['IPAddress']} reported an observation from outside every CIDR "
            f"GetCheckerIpRanges publishes ({len(cidrs)} ranges); an observation from an "
            f"unpublished address is not a Route 53 health checker"
        )
    regions = {entry["Region"] for entry in healthy}
    assert len(regions) >= 3, (
        f"Route 53 health checks are evaluated from at least three regions; the observations came "
        f"from {sorted(regions)!r} ({len(healthy)} observations)"
    )

    # --- break exactly one thing: the BODY. The health check is not touched. ---
    _put_body(s3, bucket, _WITHOUT)
    changed = _served_body(s3, bucket)
    assert _MARKER not in changed and _WITHOUT in changed, (
        f"the rewritten body must no longer contain {_MARKER!r} and must contain {_WITHOUT!r}, "
        f"got {changed!r}"
    )

    _unhealthy, failure_reports = _await_all(
        r53, hc_id, lambda s: s.startswith("Failure"),
        f"every Route 53 checker to report Failure for {host} once its body no longer contains "
        f"{_MARKER!r}",
    )
    # A content failure, not a transport failure: a checker that could not connect, could not
    # resolve the name or timed out would also report "Failure", and grading that as a
    # string-match failure would let a target that simply broke the endpoint pass.
    assert all("string" in report.lower() for report in failure_reports), (
        f"each Failure must name string matching as the reason -- a connect, DNS or timeout "
        f"failure is a different fact about the endpoint, not about SearchString: "
        f"{failure_reports!r}"
    )

    # --- effect-absent, at the health check: nothing about the CONFIG changed. ---
    during = r53.get_health_check(HealthCheckId=hc_id)["HealthCheck"]
    assert during["HealthCheckVersion"] == baseline_version, (
        f"nothing updated the health check, so HealthCheckVersion must still be "
        f"{baseline_version}, got {during['HealthCheckVersion']}"
    )
    assert during["HealthCheckConfig"]["SearchString"] == _MARKER, (
        f"SearchString must be untouched at {_MARKER!r}, got "
        f"{during['HealthCheckConfig'].get('SearchString')!r}"
    )
    assert during["HealthCheckConfig"]["Inverted"] is False, (
        f"Inverted must still be False -- the flip must be attributable to the body alone: "
        f"{during['HealthCheckConfig']!r}"
    )

    # --- restore, and demand the identical wiring report healthy again. ---
    _put_body(s3, bucket, _MARKER + " restored")
    restored_body = _served_body(s3, bucket)
    assert _MARKER in restored_body, (
        f"the restored body must contain {_MARKER!r} again, got {restored_body!r}"
    )
    _again, again_reports = _await_all(
        r53, hc_id, lambda s: s.startswith("Success"),
        f"every Route 53 checker to report Success for {host} again once {_MARKER!r} is back in "
        f"the body",
    )
    assert healthy_reports and again_reports, (
        f"both healthy phases must have produced per-checker reports: {healthy_reports!r} then "
        f"{again_reports!r}"
    )
    after = r53.get_health_check(HealthCheckId=hc_id)["HealthCheck"]
    assert after["HealthCheckVersion"] == baseline_version, (
        f"the whole three-phase flip must have happened with the health check untouched, but "
        f"HealthCheckVersion moved from {baseline_version} to {after['HealthCheckVersion']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
