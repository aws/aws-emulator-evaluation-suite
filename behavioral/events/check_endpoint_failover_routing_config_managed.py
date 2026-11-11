"""endpoint-failover-routing-config-managed."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "endpoint-failover-routing-config-managed"
GROUP = "server-side"
SERVICES = ["events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEndpoint with a failover RoutingConfig moves from CREATING to ACTIVE on its own,
    gets a server-assigned EndpointId and EndpointUrl, and DescribeEndpoint returns the exact
    FailoverConfig supplied at creation."""
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
    # Secondary.Route must name a region other than the primary bus's; either literal works.
    secondary_region = "us-west-2" if primary_region != "us-west-2" else "us-east-1"
    primary_bus_arn = f"arn:aws:events:{primary_region}:{account_id}:event-bus/default"
    secondary_bus_arn = f"arn:aws:events:{secondary_region}:{account_id}:event-bus/default"

    endpoint_name = ctx.unique_name("sim2real-behav-ep-")
    routing_config = {
        "FailoverConfig": {
            "Primary": {"HealthCheck": health_check_arn},
            "Secondary": {"Route": secondary_region},
        }
    }
    created = events.create_endpoint(
        Name=endpoint_name,
        RoutingConfig=routing_config,
        EventBuses=[{"EventBusArn": primary_bus_arn}, {"EventBusArn": secondary_bus_arn}],
        ReplicationConfig={"State": "DISABLED"},
    )
    ctx.on_cleanup(lambda: events.delete_endpoint(Name=endpoint_name))

    assert created["State"] in ("CREATING", "ACTIVE"), (
        f"expected CreateEndpoint's own State to be CREATING or ACTIVE, got {created.get('State')!r}"
    )

    final = _poll_until_terminal(ctx, events, endpoint_name, timeout_s=90.0)
    assert final["State"] == "ACTIVE", f"endpoint did not reach ACTIVE: {final}"
    # server-managed identifiers were assigned, not supplied by the caller
    assert final["EndpointId"], f"expected a server-assigned EndpointId, got {final.get('EndpointId')!r}"
    assert final["EndpointUrl"], f"expected a server-assigned EndpointUrl, got {final.get('EndpointUrl')!r}"

    assert final["RoutingConfig"]["FailoverConfig"]["Primary"]["HealthCheck"] == health_check_arn, (
        "Primary.HealthCheck drifted: sent "
        f"{health_check_arn!r} got {final['RoutingConfig']['FailoverConfig']['Primary'].get('HealthCheck')!r}"
    )
    assert final["RoutingConfig"]["FailoverConfig"]["Secondary"]["Route"] == secondary_region, (
        "Secondary.Route drifted: sent "
        f"{secondary_region!r} got {final['RoutingConfig']['FailoverConfig']['Secondary'].get('Route')!r}"
    )


def _poll_until_terminal(ctx: Any, events: Any, endpoint_name: str, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = events.describe_endpoint(Name=endpoint_name)
        if last.get("State") != "CREATING":
            return last
        time.sleep(3.0)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
