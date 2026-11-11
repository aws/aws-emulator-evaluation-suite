"""endpoint-routing-config-round-trip."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "endpoint-routing-config-round-trip"
GROUP = "representation"
SERVICES = ["events"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The exact health-check ARN, secondary-region string, and the two EventBuses ARNs
    (in the order supplied) survive CreateEndpoint and come back byte-identical from
    DescribeEndpoint -- no re-casing, re-ordering, or ARN-shape normalization.
    """
    events = ctx.client("events")
    route53 = ctx.client("route53")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    caller_ref = ctx.unique_name("sim2real-behav-hc-")
    hc = route53.create_health_check(
        CallerReference=caller_ref,
        # the endpoint needs only a health-check ARN; a CALCULATED check has no target to probe
        HealthCheckConfig={"Type": "CALCULATED", "ChildHealthChecks": [], "HealthThreshold": 0},
    )
    health_check_id = hc["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_health_check(HealthCheckId=health_check_id))
    health_check_arn = f"arn:aws:route53:::healthcheck/{health_check_id}"

    primary_region = ctx.region
    # A real secondary AWS Region for the failover config -- not a resource-region hardcode.
    secondary_region = "us-west-2" if primary_region != "us-west-2" else "us-east-1"
    # Mixed-case, punctuated name to make "byte-identical" a meaningful assertion.
    endpoint_name = ctx.unique_name("Sim2Real-Behav.Endpoint_")
    primary_bus_arn = f"arn:aws:events:{primary_region}:{account_id}:event-bus/default"
    secondary_bus_arn = f"arn:aws:events:{secondary_region}:{account_id}:event-bus/default"
    input_event_buses = [{"EventBusArn": primary_bus_arn}, {"EventBusArn": secondary_bus_arn}]
    input_routing_config = {
        "FailoverConfig": {
            "Primary": {"HealthCheck": health_check_arn},
            "Secondary": {"Route": secondary_region},
        }
    }

    events.create_endpoint(
        Name=endpoint_name,
        RoutingConfig=input_routing_config,
        EventBuses=input_event_buses,
        ReplicationConfig={"State": "DISABLED"},
    )
    ctx.on_cleanup(lambda: events.delete_endpoint(Name=endpoint_name))

    final = _poll_until_terminal(ctx, events, endpoint_name, timeout_s=90.0)

    # The endpoint must have actually come up -- otherwise a target that fails creation but
    # still echoes the requested config back would pass this check for the wrong reason.
    assert final["State"] == "ACTIVE", f"endpoint did not reach ACTIVE: {final}"
    assert final["Name"] == endpoint_name
    assert final["EventBuses"] == input_event_buses, (
        f"EventBuses drifted: sent {input_event_buses!r} got {final['EventBuses']!r}"
    )
    assert final["RoutingConfig"] == input_routing_config, (
        f"RoutingConfig drifted: sent {input_routing_config!r} got {final['RoutingConfig']!r}"
    )
    # Confirm no case-folding of the region string tucked inside Secondary.Route.
    assert final["RoutingConfig"]["FailoverConfig"]["Secondary"]["Route"] == secondary_region


def _poll_until_terminal(ctx: Any, events: Any, endpoint_name: str, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = events.describe_endpoint(Name=endpoint_name)
        if last.get("State") != "CREATING":
            return last
        time.sleep(3.0)
    raise TimeoutError(
        f"endpoint {endpoint_name!r} still CREATING after {timeout_s}s: last={last}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
