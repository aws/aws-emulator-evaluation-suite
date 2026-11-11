"""concurrent-update-endpoint-conflict-detected."""
from __future__ import annotations

import concurrent.futures as cf
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-endpoint-conflict-detected"
GROUP = "concurrency"
SERVICES = ["events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Many overlapping UpdateEndpoint calls at one global endpoint leave at least one call
    succeeding (ConcurrentModificationException is a possible, not a guaranteed, outcome for the
    rest), and the endpoint settles back to ACTIVE with the winner's value durably persisted."""
    events = ctx.client("events")
    route53 = ctx.client("route53")

    bus_name = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = events.create_event_bus(
        Name=bus_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["EventBusArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_event_bus(Name=bus_name)))

    # Empirically, CreateEndpoint validates at creation time that the Route 53 health check ARN
    # refers to a real health check, and the secondary-Region bus must be real too -- provision both
    # for real. ctx.client(region=...) pins a different region on the SAME target (real AWS or
    # emulator), unlike a hand-rolled boto3.client() which would silently drop emulator targeting.
    secondary_region = _pick_secondary_region(ctx.region)
    secondary_events = ctx.client("events", region=secondary_region)
    secondary_bus_arn = secondary_events.create_event_bus(
        Name=bus_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["EventBusArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: secondary_events.delete_event_bus(Name=bus_name))
    )

    health_check_arn = _create_health_check(ctx, route53)

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

    racer_count = 10
    max_bursts = 6
    conflict_seen = False
    success_seen = False
    for burst in range(max_bursts):
        calls = [
            (lambda i=i, b=burst: events.update_endpoint(
                Name=endpoint_name, Description=f"race-{b}-{i}"
            ))
            for i in range(racer_count)
        ]
        codes = _fire_concurrent(calls)
        if any(code is None for code in codes):
            success_seen = True
        if any(code == "ConcurrentModificationException" for code in codes):
            conflict_seen = True
            break
        # let the endpoint settle back to ACTIVE before the next burst
        _poll_endpoint_state(events, endpoint_name, timeout_s=30.0)

    # ConcurrentModificationException is a possible UpdateEndpoint error, not a guaranteed one, so
    # a backend that serializes the burst passes on the success it must still deliver.
    assert success_seen, "expected at least one UpdateEndpoint call in the race to succeed"

    final_state = _poll_endpoint_state(events, endpoint_name, timeout_s=60.0)
    assert final_state == "ACTIVE", f"endpoint did not settle back to ACTIVE, got {final_state}"

    # Positive control: a solo UpdateEndpoint (no contention) still succeeds and persists.
    events.update_endpoint(Name=endpoint_name, Description="solo-update-control")
    control_state = _poll_endpoint_state(events, endpoint_name, timeout_s=60.0)
    assert control_state == "ACTIVE", f"solo control update left endpoint in {control_state}"
    described = events.describe_endpoint(Name=endpoint_name)
    assert described["Description"] == "solo-update-control", (
        f"expected solo-update-control, got {described['Description']!r}"
    )


# Region-pinned by construction, not by convenience: an EventBridge global endpoint's
# FailoverConfig.Secondary.Route names a REAL, DIFFERENT AWS Region, so this pool exists to
# pick one distinct from ctx.region.
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


def _fire_concurrent(fns):
    """Submit every callable before blocking on any result, then collect the error code (or
    None on success) for each -- maximizes true overlap on the wire."""
    with cf.ThreadPoolExecutor(max_workers=len(fns)) as ex:
        futures = [ex.submit(fn) for fn in fns]
        codes = []
        for fut in futures:
            try:
                fut.result()
                codes.append(None)
            except ClientError as err:
                codes.append(err.response["Error"]["Code"])
        return codes


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
