"""endpoint-group-rejects-duplicate-region."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "endpoint-group-rejects-duplicate-region"
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
    """A second endpoint group for the same region on a listener is rejected with EndpointGroupAlreadyExistsException
    'Endpoint group already exists.', the listener keeps exactly the first, and the region can be used again once
    that group is deleted.
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
    first = ga.create_endpoint_group(
        ListenerArn=listener,
        EndpointGroupRegion=ctx.region,
        TrafficDialPercentage=100.0,
        IdempotencyToken=str(uuid.uuid4()),
    )["EndpointGroup"]["EndpointGroupArn"]

    code, message = _error(
        lambda: ga.create_endpoint_group(
            ListenerArn=listener,
            EndpointGroupRegion=ctx.region,
            IdempotencyToken=str(uuid.uuid4()),
        )
    )
    assert code == "EndpointGroupAlreadyExistsException", (
        f"a second endpoint group for region {ctx.region!r} on the same listener returned "
        f"{code!r}, expected 'EndpointGroupAlreadyExistsException'"
    )
    assert message == "Endpoint group already exists.", (
        f"a second endpoint group for region {ctx.region!r} returned message {message!r}, "
        f"expected 'Endpoint group already exists.'"
    )
    after = [g["EndpointGroupArn"] for g in _groups_of(ga, listener)]
    assert after == [first], (
        f"after the rejected create, the listener holds {after!r}, expected only {first!r}"
    )

    # Positive control: the region is not permanently spent — deleting the first endpoint group
    # lets the very same create succeed, so the rejection was the duplicate and nothing else.
    ga.delete_endpoint_group(EndpointGroupArn=first)
    assert _groups_of(ga, listener) == [], (
        f"the first endpoint group was deleted but the listener still holds "
        f"{[g['EndpointGroupArn'] for g in _groups_of(ga, listener)]!r}"
    )
    replacement = ga.create_endpoint_group(
        ListenerArn=listener,
        EndpointGroupRegion=ctx.region,
        IdempotencyToken=str(uuid.uuid4()),
    )["EndpointGroup"]["EndpointGroupArn"]
    assert [g["EndpointGroupArn"] for g in _groups_of(ga, listener)] == [replacement], (
        f"control: after deleting the duplicate-holder, the replacement endpoint group is not "
        f"the listener's only one; it holds "
        f"{[g['EndpointGroupArn'] for g in _groups_of(ga, listener)]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
