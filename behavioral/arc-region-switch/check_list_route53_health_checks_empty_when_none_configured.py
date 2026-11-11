"""list-route53-health-checks-empty-when-none-configured."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-route53-health-checks-empty-when-none-configured"
GROUP = "state"
SERVICES = ["arc-region-switch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A plan with no Route53HealthCheck execution block lists zero Route 53 health checks, while a
    twin plan with one wired to a real hosted zone record converges to a non-empty list.
    """
    arc = ctx.client("arc-region-switch")
    route53 = ctx.client("route53")
    region_a, region_b = _pick_regions(ctx)
    role_arn = _dummy_role_arn(ctx)

    hosted_zone_id, record_name = _create_hosted_zone_with_record(ctx, route53)

    empty_arn = arc.create_plan(
        name=_plan_name(ctx),
        regions=[region_a, region_b],
        recoveryApproach="activePassive",
        primaryRegion=region_a,
        executionRole=role_arn,
        workflows=[{"workflowTargetAction": "activate"}],
    )["plan"]["arn"]
    ctx.on_cleanup(lambda: arc.delete_plan(arn=empty_arn))

    configured_arn = arc.create_plan(
        name=_plan_name(ctx),
        regions=[region_a, region_b],
        recoveryApproach="activePassive",
        primaryRegion=region_a,
        executionRole=role_arn,
        workflows=[
            {
                "workflowTargetAction": "activate",
                "steps": [
                    {
                        "name": "HealthCheck",
                        "executionBlockType": "Route53HealthCheck",
                        "executionBlockConfiguration": {
                            "route53HealthCheckConfig": {
                                "hostedZoneId": hosted_zone_id,
                                "recordName": record_name,
                            }
                        },
                    }
                ],
            }
        ],
    )["plan"]["arn"]
    ctx.on_cleanup(lambda: _delete_plan_and_health_checks(arc, route53, configured_arn))

    configured = _poll_until(
        lambda: arc.list_route53_health_checks(arn=configured_arn)["healthChecks"],
        lambda checks: len(checks) > 0,
        timeout_s=180,
        interval_s=5,
    )
    assert len(configured) > 0, (
        f"expected the configured plan {configured_arn} to accrue at least one Route 53 health "
        f"check for hostedZoneId={hosted_zone_id} recordName={record_name}, got none"
    )
    assert all(c["hostedZoneId"] == hosted_zone_id for c in configured), (
        f"expected every listed health check's hostedZoneId to be {hosted_zone_id}, "
        f"got {[c['hostedZoneId'] for c in configured]}"
    )
    assert all(c["recordName"] == record_name for c in configured), (
        f"expected every listed health check's recordName to be {record_name}, "
        f"got {[c['recordName'] for c in configured]}"
    )

    # twin control, same instant: the unconfigured plan never accrues any health checks
    empty_checks = arc.list_route53_health_checks(arn=empty_arn)["healthChecks"]
    assert empty_checks == [], (
        f"expected the plan with no ARCRoutingControl/Route53HealthCheck execution blocks "
        f"({empty_arn}) to report zero associated Route 53 health checks, got {empty_checks!r}"
    )


# ===== helpers =====
def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _pick_regions(ctx):
    # CreatePlan requires exactly two distinct Regions; region_a is ctx.region (where every call
    # in this check is dialed), region_b is only ever plan metadata -- never dialed directly.
    region_a = ctx.region
    region_b = "us-west-2" if region_a != "us-west-2" else "us-east-1"
    return region_a, region_b


def _plan_name(ctx, prefix="sim2real-arc-"):
    return ctx.unique_name(prefix)[:32].rstrip("-")


def _dummy_role_arn(ctx):
    return f"arn:aws:iam::{_account_id(ctx)}:role/{ctx.unique_name('sim2real-dummy-role-')}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_hosted_zone_with_record(ctx, route53):
    zone_name = f"{ctx.unique_name('sim2real-arc-')}.test."
    zone = route53.create_hosted_zone(
        Name=zone_name,
        CallerReference=ctx.unique_name("sim2real-arc-hz-"),
    )
    hosted_zone_id = zone["HostedZone"]["Id"].removeprefix("/hostedzone/")

    def _delete_zone():
        try:
            route53.delete_hosted_zone(Id=hosted_zone_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchHostedZone":
                raise

    ctx.on_cleanup(_delete_zone)

    record_name = f"health.{zone_name}"
    route53.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": {
                        "Name": record_name,
                        "Type": "A",
                        "TTL": 60,
                        "ResourceRecords": [{"Value": "203.0.113.1"}],
                    },
                }
            ]
        },
    )

    def _delete_record():
        try:
            route53.change_resource_record_sets(
                HostedZoneId=hosted_zone_id,
                ChangeBatch={
                    "Changes": [
                        {
                            "Action": "DELETE",
                            "ResourceRecordSet": {
                                "Name": record_name,
                                "Type": "A",
                                "TTL": 60,
                                "ResourceRecords": [{"Value": "203.0.113.1"}],
                            },
                        }
                    ]
                },
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "HostedZoneNotFound",
                "NoSuchHealthCheck",
                "NoSuchHostedZone",
            ):
                raise

    ctx.on_cleanup(_delete_record)
    return hosted_zone_id, record_name


def _delete_plan_and_health_checks(arc, route53, arn):
    try:
        health_checks = arc.list_route53_health_checks(arn=arn)["healthChecks"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        health_checks = []
    try:
        arc.delete_plan(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    for hc in health_checks:
        hc_id = hc.get("healthCheckId")
        if not hc_id:
            continue
        try:
            route53.delete_health_check(HealthCheckId=hc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchHealthCheck":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
