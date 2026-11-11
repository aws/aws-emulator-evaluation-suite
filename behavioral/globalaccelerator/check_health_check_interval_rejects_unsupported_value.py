"""health-check-interval-rejects-unsupported-value."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "health-check-interval-rejects-unsupported-value"
GROUP = 'negative'
SERVICES = ['globalaccelerator']


def _error(fn):
    """Return the (code, message) fn() raised; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _retry(fn, codes, budget=600.0, delay=10.0):
    """Call fn() until it stops raising one of `codes`; re-raise anything else."""
    deadline = time.monotonic() + budget
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in codes or time.monotonic() > deadline:
                raise
            time.sleep(delay)


def _delete_accelerator_net(ga, arn):
    """Undo an accelerator completely: endpoint groups, listeners, disable, delete."""
    try:
        listeners = []
        token = None
        while True:
            page = ga.list_listeners(AcceleratorArn=arn, **({"NextToken": token} if token else {}))
            listeners += page.get("Listeners", [])
            token = page.get("NextToken")
            if not token:
                break
        for listener in listeners:
            groups, gtoken = [], None
            while True:
                page = ga.list_endpoint_groups(
                    ListenerArn=listener["ListenerArn"],
                    **({"NextToken": gtoken} if gtoken else {}),
                )
                groups += page.get("EndpointGroups", [])
                gtoken = page.get("NextToken")
                if not gtoken:
                    break
            for group in groups:
                ga.delete_endpoint_group(EndpointGroupArn=group["EndpointGroupArn"])
            ga.delete_listener(ListenerArn=listener["ListenerArn"])
        ga.update_accelerator(AcceleratorArn=arn, Enabled=False)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "AcceleratorNotFoundException":
            raise
        return
    _retry(
        lambda: ga.delete_accelerator(AcceleratorArn=arn),
        codes=("AcceleratorNotDisabledException", "TransactionInProgressException"),
        budget=600.0,
    )


def _interval_of(ga, group):
    return ga.describe_endpoint_group(EndpointGroupArn=group)["EndpointGroup"][
        "HealthCheckIntervalSeconds"
    ]


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """UpdateEndpointGroup rejects HealthCheckIntervalSeconds 20 with InvalidArgumentException and its exact
    message and the interval stays 30, while 10 is accepted: the model allows 10..30, AWS only 10 or 30.
    """
    ga = ctx.client("globalaccelerator")

    accelerator = ga.create_accelerator(
        Name=ctx.unique_name("sim2real-behav-ga-"),
        IpAddressType="IPV4",
        Enabled=False,
        IdempotencyToken=str(uuid.uuid4()),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Accelerator"]
    arn = accelerator["AcceleratorArn"]
    ctx.on_cleanup(lambda: _delete_accelerator_net(ga, arn))

    listener = ga.create_listener(
        AcceleratorArn=arn,
        PortRanges=[{"FromPort": 80, "ToPort": 80}],
        Protocol="TCP",
        IdempotencyToken=str(uuid.uuid4()),
    )["Listener"]["ListenerArn"]
    group = ga.create_endpoint_group(
        ListenerArn=listener,
        EndpointGroupRegion=ctx.region,
        HealthCheckPort=80,
        HealthCheckProtocol="TCP",
        HealthCheckIntervalSeconds=30,
        ThresholdCount=3,
        IdempotencyToken=str(uuid.uuid4()),
    )["EndpointGroup"]["EndpointGroupArn"]
    assert _interval_of(ga, group) == 30, (
        f"setup: the endpoint group was created with interval 30 but reports "
        f"{_interval_of(ga, group)!r}"
    )

    code, message = _error(
        lambda: ga.update_endpoint_group(
            EndpointGroupArn=group, HealthCheckIntervalSeconds=20
        )
    )
    assert code == "InvalidArgumentException", (
        f"UpdateEndpointGroup with HealthCheckIntervalSeconds=20 returned {code!r}, expected "
        f"'InvalidArgumentException'"
    )
    expected = "Invalid HealthCheck Interval Seconds: 20 expected values are: 10 or 30"
    assert message == expected, (
        f"UpdateEndpointGroup with HealthCheckIntervalSeconds=20 returned message {message!r}, "
        f"expected {expected!r}"
    )
    assert _interval_of(ga, group) == 30, (
        f"the rejected update changed the endpoint group anyway: interval is now "
        f"{_interval_of(ga, group)!r}, expected 30"
    )

    # Positive control: the only other supported value goes through on the same endpoint group,
    # so the rejection above is the value 20 and not a broken update path.
    ga.update_endpoint_group(EndpointGroupArn=group, HealthCheckIntervalSeconds=10)
    assert _interval_of(ga, group) == 10, (
        f"control: interval 10 is supported but the endpoint group reports "
        f"{_interval_of(ga, group)!r} after the update"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
