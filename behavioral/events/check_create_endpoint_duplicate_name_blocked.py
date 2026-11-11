"""create-endpoint-duplicate-name-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-endpoint-duplicate-name-blocked"
GROUP = "overly-permissive"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEndpoint with a Name that already belongs to an existing global endpoint is
    rejected with ResourceAlreadyExistsException instead of silently succeeding or overwriting
    the original endpoint's configuration."""
    events = ctx.client("events")
    route53 = ctx.client("route53")

    bus_name = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = events.create_event_bus(Name=bus_name, Tags=[{"Key": "sim2real", "Value": "1"}])[
        "EventBusArn"
    ]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_event_bus(Name=bus_name)))

    # Empirically, CreateEndpoint validates at creation time that the Route 53 health check ARN
    # refers to a real health check, and the secondary-Region bus must be real too -- provision both
    # for real.
    secondary_region = _pick_secondary_region(ctx.region)
    secondary_events = ctx.client("events", region=secondary_region)
    secondary_bus_arn = secondary_events.create_event_bus(
        Name=bus_name, Tags=[{"Key": "sim2real", "Value": "1"}]
    )["EventBusArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: secondary_events.delete_event_bus(Name=bus_name))
    )

    health_check_arn = _create_health_check(ctx, route53)

    routing_config = {
        "FailoverConfig": {
            "Primary": {"HealthCheck": health_check_arn},
            "Secondary": {"Route": secondary_region},
        }
    }
    event_buses = [{"EventBusArn": bus_arn}, {"EventBusArn": secondary_bus_arn}]

    endpoint_name = ctx.unique_name("sim2real-behav-ep-")
    events.create_endpoint(
        Name=endpoint_name,
        RoutingConfig=routing_config,
        EventBuses=event_buses,
        ReplicationConfig={"State": "DISABLED"},
        Description="original",
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_endpoint(Name=endpoint_name)))
    state = _poll_endpoint_state(events, endpoint_name, timeout_s=60.0)
    assert state == "ACTIVE", f"endpoint never reached ACTIVE, last observed state={state}"

    err = _error(
        lambda: events.create_endpoint(
            Name=endpoint_name,
            RoutingConfig=routing_config,
            EventBuses=event_buses,
            ReplicationConfig={"State": "DISABLED"},
            Description="duplicate-attempt",
        )
    )
    expected = ("ResourceAlreadyExistsException", f"Endpoint {endpoint_name} already exists.")
    assert err == expected, f"expected {expected}, got {err}"

    # Effect absent: the original endpoint's Description was NOT overwritten by the rejected
    # duplicate-name create call.
    described = events.describe_endpoint(Name=endpoint_name)
    assert described["Description"] == "original", (
        f"duplicate CreateEndpoint must not mutate the existing endpoint, got Description="
        f"{described['Description']!r}"
    )

    # Positive control: CreateEndpoint with a genuinely different Name (same underlying buses
    # and health check) still succeeds -- proving CreateEndpoint works in general, and the
    # rejection above is specifically about the name collision.
    other_name = ctx.unique_name("sim2real-behav-ep2-")
    events.create_endpoint(
        Name=other_name,
        RoutingConfig=routing_config,
        EventBuses=event_buses,
        ReplicationConfig={"State": "DISABLED"},
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_endpoint(Name=other_name)))
    other_state = _poll_endpoint_state(events, other_name, timeout_s=60.0)
    assert other_state == "ACTIVE", f"control endpoint never reached ACTIVE, got {other_state}"


# A pool of real, distinct AWS regions to pick a SECONDARY region from -- EventBridge global
# endpoints require the failover Secondary.Route to be a genuine other region, not a literal
# target region of this check's own resources.
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
    return f"arn:aws:route53:::healthcheck/{health_check_id}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")


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
