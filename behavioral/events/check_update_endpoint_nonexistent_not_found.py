"""update-endpoint-nonexistent-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-endpoint-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateEndpoint targeting a name that was never created fails with
    ResourceNotFoundException (no phantom endpoint gets created), while updating a real
    endpoint's Description succeeds and persists."""
    events = ctx.client("events")
    name = _create_endpoint(ctx)

    bogus = ctx.unique_name("sim2real-behav-noendpoint-")
    not_found = f"Endpoint {bogus} does not exist in region {ctx.region}."
    code, message = _error(
        lambda: events.update_endpoint(Name=bogus, Description="should-not-apply")
    )
    assert code == "ResourceNotFoundException", f"UpdateEndpoint on {bogus}: got {code}"
    assert message == not_found, f"UpdateEndpoint message {message!r}, expected {not_found!r}"

    # effect absent: the failed update did not create a resource under the bogus name
    absent_code, absent_message = _error(lambda: events.describe_endpoint(Name=bogus))
    assert absent_code == "ResourceNotFoundException", (
        f"DescribeEndpoint on {bogus}: got {absent_code}"
    )
    assert absent_message == not_found, (
        f"DescribeEndpoint message {absent_message!r}, expected {not_found!r}"
    )

    # positive control: updating the endpoint that actually exists succeeds and persists
    new_description = f"updated-{name}"
    events.update_endpoint(Name=name, Description=new_description)

    def _updated() -> bool:
        return events.describe_endpoint(Name=name).get("Description") == new_description

    assert _poll_until(_updated, timeout_s=60.0, interval_s=2.0), (
        "endpoint description never reflected the successful UpdateEndpoint call"
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
    r53.change_tags_for_resource(
        ResourceType="healthcheck",
        ResourceId=hc_id,
        AddTags=[{"Key": "sim2real", "Value": "behavioral"}],
    )

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
    actually-existing resource. Waits for the endpoint to leave CREATING (a mutating call
    against a still-provisioning endpoint fails with ConcurrentModificationException)."""
    events = ctx.client("events")
    account_id = _account_id(ctx)
    # global endpoint failover requires a second, distinct region to route to -- not the region
    # under test, so this is a region-pinned resource requirement, not an assumption about ctx.region
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
    # TagResource covers only rules and event buses (per the events service model's own docs);
    # EventBridge global endpoints have no tagging API, so this resource is untagged by necessity.

    def _cleanup():
        try:
            events.delete_endpoint(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    def _active() -> bool:
        return events.describe_endpoint(Name=name).get("State") == "ACTIVE"

    assert _poll_until(_active, timeout_s=90.0, interval_s=3.0), (
        f"endpoint {name} never reached ACTIVE within 90s"
    )
    return name



def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
