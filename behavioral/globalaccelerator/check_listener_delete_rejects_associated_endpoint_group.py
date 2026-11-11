"""listener-delete-rejects-associated-endpoint-group."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "listener-delete-rejects-associated-endpoint-group"
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
        for listener in _listeners_of(ga, arn):
            for group in _groups_of(ga, listener["ListenerArn"]):
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


def _listeners_of(ga, arn):
    listeners, token = [], None
    while True:
        page = ga.list_listeners(AcceleratorArn=arn, **({"NextToken": token} if token else {}))
        listeners += page.get("Listeners", [])
        token = page.get("NextToken")
        if not token:
            return listeners


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


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """DeleteListener on a listener with an endpoint group fails with AssociatedEndpointGroupFoundException and its
    exact message and leaves both in place, and the same call succeeds once the endpoint group is deleted.
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
        PortRanges=[{"FromPort": 443, "ToPort": 443}],
        Protocol="TCP",
        IdempotencyToken=str(uuid.uuid4()),
    )["Listener"]["ListenerArn"]
    group = ga.create_endpoint_group(
        ListenerArn=listener,
        EndpointGroupRegion=ctx.region,
        TrafficDialPercentage=100.0,
        IdempotencyToken=str(uuid.uuid4()),
    )["EndpointGroup"]["EndpointGroupArn"]

    code, message = _error(lambda: ga.delete_listener(ListenerArn=listener))
    assert code == "AssociatedEndpointGroupFoundException", (
        f"DeleteListener on a listener with an endpoint group returned {code!r}, expected "
        f"'AssociatedEndpointGroupFoundException'"
    )
    expected = (
        f"Cannot delete listener {listener} because an associated endpoint group was found."
    )
    assert message == expected, (
        f"DeleteListener on a listener with an endpoint group returned message {message!r}, "
        f"expected {expected!r}"
    )
    surviving = [listener_["ListenerArn"] for listener_ in _listeners_of(ga, arn)]
    assert surviving == [listener], (
        f"after the refused delete the accelerator holds listeners {surviving!r}, expected only "
        f"{listener!r}"
    )
    assert [g["EndpointGroupArn"] for g in _groups_of(ga, listener)] == [group], (
        f"the refused DeleteListener disturbed the endpoint group; the listener now holds "
        f"{[g['EndpointGroupArn'] for g in _groups_of(ga, listener)]!r}"
    )

    # Positive control: the identical DeleteListener call succeeds once the endpoint group is
    # deleted, so the refusal was the association and not an undeletable listener.
    ga.delete_endpoint_group(EndpointGroupArn=group)
    ga.delete_listener(ListenerArn=listener)
    assert _listeners_of(ga, arn) == [], (
        f"control: after deleting its endpoint group the listener should delete, but the "
        f"accelerator still holds "
        f"{[listener_['ListenerArn'] for listener_ in _listeners_of(ga, arn)]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
