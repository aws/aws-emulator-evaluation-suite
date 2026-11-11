"""delete-endpoint-nonexistent-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-endpoint-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteEndpoint on a never-created name succeeds (despite the documented ResourceNotFound),
    stably across two names, without disturbing a real endpoint, which then deletes normally."""
    events = ctx.client("events")
    name = _create_endpoint(ctx)

    bogus = ctx.unique_name("sim2real-behav-noendpoint-")
    # A ClientError here fails the check: real AWS answers success.
    events.delete_endpoint(Name=bogus)

    # repeat with a distinct nonexistent name: the idempotent-success result is stable
    other_bogus = ctx.unique_name("sim2real-behav-noendpoint-")
    events.delete_endpoint(Name=other_bogus)

    # effect absent: the silently-succeeded delete on bogus names did not touch our real endpoint
    described = events.describe_endpoint(Name=name)
    assert described["Name"] == name, f"expected real endpoint {name!r} unaffected, got {described.get('Name')!r}"

    # positive control: deleting the endpoint that actually exists succeeds
    events.delete_endpoint(Name=name)

    def _gone() -> bool:
        try:
            events.describe_endpoint(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return True
            raise
        return False

    assert _poll_until(_gone, timeout_s=60.0, interval_s=2.0), (
        "endpoint still describable after a successful DeleteEndpoint call"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_health_check(ctx):
    """Create a Route53 health check; CreateEndpoint requires the health-check ARN to exist."""
    r53 = ctx.client("route53")
    caller_ref = ctx.unique_name("sim2real-behav-hc-")
    resp = r53.create_health_check(
        CallerReference=caller_ref,
        HealthCheckConfig={
            "Type": "CALCULATED",
            "HealthThreshold": 0,
        },
    )
    hc_id = resp["HealthCheck"]["Id"]

    def _cleanup():
        try:
            r53.delete_health_check(HealthCheckId=hc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchHealthCheck":
                raise

    ctx.on_cleanup(_cleanup)
    return f"arn:aws:route53:::healthcheck/{hc_id}"


def _create_endpoint(ctx):
    """Create a global endpoint over the default buses and wait for ACTIVE; mutating a
    still-provisioning endpoint fails with ConcurrentModificationException."""
    events = ctx.client("events")
    account_id = _account_id(ctx)
    # region literals: a global endpoint's RoutingConfig requires a real, distinct secondary
    # Region to fail over to, not the check's own region pin.
    secondary_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    name = ctx.unique_name("sim2real-behav-endpoint-")
    health_check_arn = _create_health_check(ctx)
    events.create_endpoint(
        Name=name,
        RoutingConfig={
            "FailoverConfig": {
                "Primary": {"HealthCheck": health_check_arn},
                "Secondary": {"Route": secondary_region},
            }
        },
        ReplicationConfig={"State": "DISABLED"},
        EventBuses=[
            {"EventBusArn": f"arn:aws:events:{ctx.region}:{account_id}:event-bus/default"},
            {"EventBusArn": f"arn:aws:events:{secondary_region}:{account_id}:event-bus/default"},
        ],
    )

    def _cleanup():
        try:
            events.delete_endpoint(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    def _active() -> bool:
        return events.describe_endpoint(Name=name).get("State") == "ACTIVE"

    _poll_until(_active, timeout_s=90.0, interval_s=3.0)
    return name



def _poll_until(predicate, *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return predicate()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
