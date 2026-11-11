"""update-endpoint-changes-routing-config."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-endpoint-changes-routing-config"
GROUP = "state-machine"
SERVICES = ["events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateEndpoint mutates RoutingConfig; DescribeEndpoint reflects the new values, not the old ones."""
    events = ctx.client("events")
    route53 = ctx.client("route53")

    bus_name = ctx.unique_name("sim2real-behav-bus-")
    bus_tags = [{"Key": "sim2real-behav-check", "Value": CHECK}]
    bus_arn = events.create_event_bus(Name=bus_name, Tags=bus_tags)["EventBusArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_event_bus(Name=bus_name)))

    # Empirically (verified against real AWS), CreateEndpoint validates at creation time that the
    # Route 53 health check ARN refers to a real health check, and the secondary-Region bus must
    # be real too -- provision both for real. ctx.client()'s `region` override keeps this on the
    # SAME target as the primary client (real AWS in that region on the real-AWS arm, the shared
    # emulator endpoint on the emulator arm) -- a hand-rolled boto3.client() with no endpoint_url
    # would send this call straight to real AWS even when scoring an emulator.
    secondary_region = _pick_secondary_region(ctx.region)
    secondary_events = ctx.client("events", region=secondary_region)
    secondary_bus_arn = secondary_events.create_event_bus(Name=bus_name, Tags=bus_tags)["EventBusArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: secondary_events.delete_event_bus(Name=bus_name))
    )

    initial_health_check = _create_health_check(ctx, route53)
    updated_health_check = _create_health_check(ctx, route53)

    endpoint_name = ctx.unique_name("sim2real-behav-ep-")
    events.create_endpoint(
        Name=endpoint_name,
        RoutingConfig={
            "FailoverConfig": {
                "Primary": {"HealthCheck": initial_health_check},
                "Secondary": {"Route": secondary_region},
            }
        },
        EventBuses=[{"EventBusArn": bus_arn}, {"EventBusArn": secondary_bus_arn}],
        ReplicationConfig={"State": "DISABLED"},
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_endpoint(Name=endpoint_name)))

    state = _poll_endpoint_state(events, endpoint_name, timeout_s=60.0)
    assert state == "ACTIVE", f"endpoint never reached ACTIVE, last observed state={state}"

    created = events.describe_endpoint(Name=endpoint_name)
    assert created["RoutingConfig"]["FailoverConfig"]["Secondary"]["Route"] == secondary_region
    assert created["RoutingConfig"]["FailoverConfig"]["Primary"]["HealthCheck"] == initial_health_check

    events.update_endpoint(
        Name=endpoint_name,
        RoutingConfig={
            "FailoverConfig": {
                "Primary": {"HealthCheck": updated_health_check},
                "Secondary": {"Route": secondary_region},
            }
        },
    )

    state = _poll_endpoint_state(events, endpoint_name, timeout_s=60.0)
    assert state == "ACTIVE", f"endpoint never returned to ACTIVE after update, last observed state={state}"

    updated = events.describe_endpoint(Name=endpoint_name)
    new_health_check = updated["RoutingConfig"]["FailoverConfig"]["Primary"]["HealthCheck"]
    assert new_health_check == updated_health_check, "expected updated Primary.HealthCheck"
    assert new_health_check != initial_health_check


# Candidates for the SECONDARY failover region only -- never a pin on the primary/subject
# resource, which always follows ctx.region. Global Endpoints require two distinct real
# regions, so this is a fixed pool to pick an arbitrary "other" region from.
_REGION_POOL = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-2"]


def _pick_secondary_region(primary_region, exclude=()):
    for region in _REGION_POOL:
        if region != primary_region and region not in exclude:
            return region
    return "us-east-1"


def _create_health_check(ctx, route53):
    health_check_id = route53.create_health_check(
        CallerReference=ctx.unique_name("sim2real-behav-hc-"),
        HealthCheckConfig={
            "Type": "HTTP",
            "FullyQualifiedDomainName": "sim2real-hc-target.invalid",
            "Port": 80,
            "ResourcePath": "/",
            "RequestInterval": 30,
            "FailureThreshold": 3,
        },
    )["HealthCheck"]["Id"]
    ctx.on_cleanup(
        lambda: _ignore_route53_not_found(
            lambda: route53.delete_health_check(HealthCheckId=health_check_id)
        )
    )
    route53.change_tags_for_resource(
        ResourceType="healthcheck",
        ResourceId=health_check_id,
        AddTags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    return f"arn:aws:route53:::healthcheck/{health_check_id}"


def _error_code(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    return None


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _ignore_route53_not_found(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchHealthCheck":
            raise



def _poll_endpoint_state(events, name, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = events.describe_endpoint(Name=name)["State"]
        if state in ("ACTIVE", "CREATE_FAILED", "DELETE_FAILED", "UPDATE_FAILED"):
            return state
        time.sleep(interval_s)
    return state


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
