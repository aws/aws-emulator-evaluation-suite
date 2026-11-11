"""endpoint-lifecycle-create-active-delete-404."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "endpoint-lifecycle-create-active-delete-404"
GROUP = "state-machine"
SERVICES = ["events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEndpoint reaches ACTIVE (observed via DescribeEndpoint); DeleteEndpoint then 404s."""
    events = ctx.client("events")
    route53 = ctx.client("route53")
    sts = ctx.client("sts")
    sts.get_caller_identity()["Account"]

    bus_name = ctx.unique_name("sim2real-behav-bus-")
    bus_tags = [{"Key": "sim2real-behav-check", "Value": CHECK}]
    bus_arn = events.create_event_bus(Name=bus_name, Tags=bus_tags)["EventBusArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_event_bus(Name=bus_name)))

    # CreateEndpoint validates at creation time that
    # the Route 53 health check ARN refers to a real health check (ValidationException otherwise),
    # so provision one for real. The secondary-Region bus is created through a ctx client pinned
    # to that region.
    secondary_region = _pick_secondary_region(ctx.region)
    secondary_events = ctx.client("events", region=secondary_region)
    secondary_bus_arn = secondary_events.create_event_bus(Name=bus_name, Tags=bus_tags)["EventBusArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: secondary_events.delete_event_bus(Name=bus_name))
    )

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
    ctx.on_cleanup(lambda: _ignore_route53_not_found(lambda: route53.delete_health_check(
        HealthCheckId=health_check_id
    )))
    route53.change_tags_for_resource(
        ResourceType="healthcheck",
        ResourceId=health_check_id,
        AddTags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    health_check_arn = f"arn:aws:route53:::healthcheck/{health_check_id}"

    endpoint_name = ctx.unique_name("sim2real-behav-ep-")
    events.create_endpoint(
        Name=endpoint_name,
        RoutingConfig={
            "FailoverConfig": {
                "Primary": {"HealthCheck": health_check_arn},
                "Secondary": {"Route": secondary_region},
            }
        },
        EventBuses=[{"EventBusArn": bus_arn}, {"EventBusArn": secondary_bus_arn}],
        ReplicationConfig={"State": "DISABLED"},
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_endpoint(Name=endpoint_name)))

    state = _poll_endpoint_state(events, endpoint_name, timeout_s=60.0)
    assert state == "ACTIVE", f"endpoint never reached ACTIVE, last observed state={state}"

    events.delete_endpoint(Name=endpoint_name)

    not_found = ("ResourceNotFoundException", f"Endpoint {endpoint_name} does not exist in region {ctx.region}.")
    deadline = time.monotonic() + 60.0
    err = None
    while time.monotonic() < deadline:
        try:
            events.describe_endpoint(Name=endpoint_name)
        except ClientError as exc:
            err = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            if err[0] == "ResourceNotFoundException":
                break
        time.sleep(2.0)
    assert err == not_found, f"expected {not_found!r} after delete, got {err!r}"

    # a deleted endpoint is not just unreadable -- it is also unmutable, never resurrected
    # by a write targeting its old name (UpdateEndpoint on a
    # never-existed name also raises ResourceNotFoundException; the deleted-name case must match).
    mutate_err = _error(
        lambda: events.update_endpoint(Name=endpoint_name, Description="post-delete-should-not-apply")
    )
    assert mutate_err == not_found, (
        f"expected UpdateEndpoint on a deleted endpoint to raise {not_found!r}, got {mutate_err!r}"
    )


_REGION_POOL = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-2"]


def _pick_secondary_region(primary_region, exclude=()):
    for region in _REGION_POOL:
        if region != primary_region and region not in exclude:
            return region
    return "us-east-1"


def _error(fn):
    """(code, message) of a call that must fail; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
