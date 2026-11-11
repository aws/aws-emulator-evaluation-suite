"""traffic-dial-rejects-percentage-above-hundred."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "traffic-dial-rejects-percentage-above-hundred"
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


def _groups_of(ga, listener):
    groups, token = [], None
    while True:
        page = ga.list_endpoint_groups(
            ListenerArn=listener, **({"NextToken": token} if token else {})
        )
        groups += page.get("EndpointGroups", [])
        token = page.get("NextToken")
        if not token:
            return groups


def _dial_of(ga, group):
    return ga.describe_endpoint_group(EndpointGroupArn=group)["EndpointGroup"][
        "TrafficDialPercentage"
    ]


_DIAL_150_MESSAGE = (
    "1 validation error detected: Value '150.0' at 'trafficRetentionPercentage' failed to "
    "satisfy constraint: Member must have value less than or equal to 100"
)


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """TrafficDialPercentage 150 is rejected with InvalidArgumentException and its exact message at create (no
    group is created) and at update (the dial stays 100), while an update to 50 is accepted.
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

    code, message = _error(
        lambda: ga.create_endpoint_group(
            ListenerArn=listener,
            EndpointGroupRegion=ctx.region,
            TrafficDialPercentage=150.0,
            IdempotencyToken=str(uuid.uuid4()),
        )
    )
    assert code == "InvalidArgumentException", (
        f"CreateEndpointGroup with TrafficDialPercentage=150 returned {code!r}, expected "
        f"'InvalidArgumentException'"
    )
    assert message == _DIAL_150_MESSAGE, (
        f"CreateEndpointGroup with TrafficDialPercentage=150 returned message {message!r}, "
        f"expected {_DIAL_150_MESSAGE!r}"
    )
    existing = _groups_of(ga, listener)
    assert existing == [], (
        f"the rejected CreateEndpointGroup created an endpoint group anyway: {existing!r}"
    )

    # Positive control: the same call with an in-range dial succeeds, so the rejection above is
    # the value 150 and not an unusable listener.
    group = ga.create_endpoint_group(
        ListenerArn=listener,
        EndpointGroupRegion=ctx.region,
        TrafficDialPercentage=100.0,
        IdempotencyToken=str(uuid.uuid4()),
    )["EndpointGroup"]["EndpointGroupArn"]
    assert _dial_of(ga, group) == 100.0, (
        f"control: the endpoint group was created with dial 100 but reports "
        f"{_dial_of(ga, group)!r}"
    )

    update_code, update_message = _error(
        lambda: ga.update_endpoint_group(EndpointGroupArn=group, TrafficDialPercentage=150.0)
    )
    assert update_code == "InvalidArgumentException", (
        f"UpdateEndpointGroup with TrafficDialPercentage=150 returned {update_code!r}, expected "
        f"'InvalidArgumentException'"
    )
    assert update_message == _DIAL_150_MESSAGE, (
        f"UpdateEndpointGroup with TrafficDialPercentage=150 returned message "
        f"{update_message!r}, expected {_DIAL_150_MESSAGE!r}"
    )
    assert _dial_of(ga, group) == 100.0, (
        f"the rejected update changed the dial anyway: it is now {_dial_of(ga, group)!r}, "
        f"expected 100.0"
    )

    # Positive control on the update path too: a partial dial is accepted and round-trips.
    ga.update_endpoint_group(EndpointGroupArn=group, TrafficDialPercentage=50.0)
    assert _dial_of(ga, group) == 50.0, (
        f"control: dial 50 is in range but the endpoint group reports {_dial_of(ga, group)!r} "
        f"after the update"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
