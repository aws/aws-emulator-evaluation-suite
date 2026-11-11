"""describe-endpoint-nonexistent-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-endpoint-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeEndpoint on an unknown endpoint name returns ResourceNotFoundException,
    while a real global endpoint keeps describing fine before and after the failed call."""
    events = ctx.client("events")
    name = _create_endpoint(ctx)

    # positive control: the endpoint we just created describes successfully
    described = events.describe_endpoint(Name=name)
    assert described["Name"] == name, (
        f"positive control failed: expected DescribeEndpoint(Name={name!r}) to return "
        f"that same name, got {described.get('Name')!r}"
    )

    bogus = ctx.unique_name("sim2real-behav-noendpoint-")
    err = _error(lambda: events.describe_endpoint(Name=bogus))
    assert err == ("ResourceNotFoundException", f"Endpoint {bogus} does not exist in region {ctx.region}."), (
        f"expected DescribeEndpoint on unknown endpoint {bogus!r} to raise "
        f"ResourceNotFoundException, got {err!r}"
    )

    # effect absent / unaffected: the real endpoint is still describable afterwards
    described_again = events.describe_endpoint(Name=name)
    assert described_again["Name"] == name, (
        f"real endpoint {name!r} should still describe fine after the unrelated "
        f"not-found lookup, got Name={described_again.get('Name')!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_health_check(ctx):
    """Create a real Route53 health check (CreateEndpoint validates the health-check ARN
    against an actually-existing Route53 resource, not just its syntactic shape) and register
    its cleanup."""
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
    """Create a real global endpoint using only always-present default event buses and a
    real Route53 health check -- CreateEndpoint validates the health-check ARN against an
    actually-existing resource."""
    events = ctx.client("events")
    account_id = _account_id(ctx)
    # A global endpoint's FailoverConfig requires two *distinct* regions; the literals
    # here are just "any region other than ctx.region", not a pin to a specific one.
    secondary_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    name = ctx.unique_name("sim2real-behav-endpoint-")
    health_check_arn = _create_health_check(ctx)
    events.create_endpoint(
        Name=name,
        RoutingConfig={
            "FailoverConfig": {"Primary": {"HealthCheck": health_check_arn},
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

def _error(fn):
    """(code, message) of a call that must fail; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected a ClientError, but the call SUCCEEDED and returned {result!r}"
    )


def _poll_until(predicate, *, timeout_s: float, interval_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval_s)
    if not predicate():
        raise TimeoutError(f"condition did not become true within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
