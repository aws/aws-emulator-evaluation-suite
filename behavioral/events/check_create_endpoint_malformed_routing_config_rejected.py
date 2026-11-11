"""create-endpoint-malformed-routing-config-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-endpoint-malformed-routing-config-rejected"
GROUP = "negative-classes"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEndpoint whose FailoverConfig omits the required Secondary is rejected with a
    ValidationException and creates no describable or listable endpoint."""
    events = ctx.client("events")
    # Client-side validation would catch the missing member; disable it so the server validates.
    raw_events = ctx.client("events", config=Config(parameter_validation=False))

    endpoint_name = ctx.unique_name("sim2real-behav-ep-")

    err = _error(
        lambda: raw_events.create_endpoint(
            Name=endpoint_name,
            RoutingConfig={
                "FailoverConfig": {
                    # Secondary is a required member of FailoverConfig -- omitted here.
                    "Primary": {
                        "HealthCheck": "arn:aws:route53:::healthcheck/00000000-0000-0000-0000-000000000000"
                    },
                }
            },
            EventBuses=[
                {"EventBusArn": f"arn:aws:events:{ctx.region}:111122223333:event-bus/sim2real-fake-a"},
                {"EventBusArn": f"arn:aws:events:{ctx.region}:111122223333:event-bus/sim2real-fake-b"},
            ],
        )
    )
    expected = (
        "ValidationException",
        "1 validation error detected: Value null at 'routingConfig.failoverConfig.secondary' "
        "failed to satisfy constraint: Member must not be null",
    )
    assert err == expected, f"expected {expected}, got {err}"

    # Effect absent: the rejected create must not have produced a describable endpoint.
    describe_err = _error(lambda: events.describe_endpoint(Name=endpoint_name))
    expected_absent = (
        "ResourceNotFoundException",
        f"Endpoint {endpoint_name} does not exist in region {ctx.region}.",
    )
    assert describe_err == expected_absent, (
        f"malformed CreateEndpoint must not create an endpoint, describe returned {describe_err}"
    )
    names = {ep["Name"] for ep in events.list_endpoints().get("Endpoints", [])}
    assert endpoint_name not in names, (
        f"malformed CreateEndpoint must not create a listable endpoint, found {endpoint_name!r} "
        f"in ListEndpoints"
    )

    # Positive control: the same credentials can still perform an ordinary, well-formed control-
    # plane operation -- this is a targeted input-validation rejection, not a broken client.
    bus_name = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_event_bus(Name=bus_name)))
    described = events.describe_event_bus(Name=bus_name)
    assert described["Name"] == bus_name, (
        f"expected positive-control event bus Name={bus_name!r}, got {described['Name']!r}"
    )


def _error(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
