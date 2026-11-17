"""endpoint-membership-survives-duplicate-add-and-absent-remove."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "endpoint-membership-survives-duplicate-add-and-absent-remove"
GROUP = "endpoints"
SERVICES = ["ec2", "globalaccelerator"]

_BUSY = ("TransactionInProgressException", "There's already a transaction in progress. Another transaction can't be processed.")


def _outcome(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _outcome(fn)
    assert got_code == code, f"expected {code}, got {got_code}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _past_transaction(fn, budget=60.0, delay=3.0):
    """Call fn() until it stops raising the fixed `_BUSY` pair; re-raise anything else."""
    deadline = time.monotonic() + budget
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) != _BUSY or time.monotonic() > deadline:
                raise
            time.sleep(delay)


def _membership(ga, group_arn):
    """{EndpointId: Weight} for every endpoint the group currently reports."""
    described = ga.describe_endpoint_group(EndpointGroupArn=group_arn)["EndpointGroup"]
    return {e["EndpointId"]: e["Weight"] for e in described.get("EndpointDescriptions", [])}


def _release_quietly(ec2, allocation_id):
    try:
        ec2.release_address(AllocationId=allocation_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidAllocationID.NotFound":
            raise


def _unwind_accelerator(ga, accelerator_arn):
    """Delete every listener and endpoint group under the accelerator, disable it, then delete it."""
    listeners, token = [], None
    while True:
        page = ga.list_listeners(
            AcceleratorArn=accelerator_arn, **({"NextToken": token} if token else {})
        )
        listeners += page.get("Listeners", [])
        token = page.get("NextToken")
        if not token:
            break
    for listener in listeners:
        groups, gtoken = [], None
        while True:
            page = ga.list_endpoint_groups(
                ListenerArn=listener["ListenerArn"], **({"NextToken": gtoken} if gtoken else {})
            )
            groups += page.get("EndpointGroups", [])
            gtoken = page.get("NextToken")
            if not gtoken:
                break
        for group in groups:
            ga.delete_endpoint_group(EndpointGroupArn=group["EndpointGroupArn"])
        ga.delete_listener(ListenerArn=listener["ListenerArn"])
    ga.update_accelerator(AcceleratorArn=accelerator_arn, Enabled=False)
    deadline = time.monotonic() + 600.0
    status = None
    while time.monotonic() < deadline:
        status = ga.describe_accelerator(AcceleratorArn=accelerator_arn)["Accelerator"]["Status"]
        if status == "DEPLOYED":
            break
        time.sleep(5.0)
    assert status == "DEPLOYED", (
        f"accelerator {accelerator_arn} did not settle to DEPLOYED within 600s of being "
        f"disabled, so it cannot be deleted; its last reported status was {status!r}"
    )
    _past_transaction(
        lambda: ga.delete_accelerator(AcceleratorArn=accelerator_arn), budget=120.0, delay=10.0
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddEndpoints refuses a second EndpointConfigurations entry for an id the group already
    holds, and RemoveEndpoints no-ops on an id the group never held; neither disturbs the group's
    real membership, and both the add and the remove work normally on an id they actually apply to.
    """
    ga = ctx.client("globalaccelerator")
    ec2 = ctx.client("ec2")

    resident = ec2.allocate_address(Domain="vpc")["AllocationId"]
    ctx.on_cleanup(lambda: _release_quietly(ec2, resident))

    accelerator_arn = ga.create_accelerator(
        Name=ctx.unique_name("sim2real-behav-ga-"),
        IpAddressType="IPV4",
        Enabled=False,
        IdempotencyToken=str(uuid.uuid4()),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Accelerator"]["AcceleratorArn"]
    ctx.on_cleanup(lambda: _unwind_accelerator(ga, accelerator_arn))

    listener_arn = ga.create_listener(
        AcceleratorArn=accelerator_arn,
        PortRanges=[{"FromPort": 5000, "ToPort": 5000}],
        Protocol="TCP",
        IdempotencyToken=str(uuid.uuid4()),
    )["Listener"]["ListenerArn"]
    group_arn = ga.create_endpoint_group(
        ListenerArn=listener_arn,
        EndpointGroupRegion=ctx.region,
        EndpointConfigurations=[{"EndpointId": resident, "Weight": 50}],
        TrafficDialPercentage=100.0,
        IdempotencyToken=str(uuid.uuid4()),
    )["EndpointGroup"]["EndpointGroupArn"]

    baseline = _membership(ga, group_arn)
    assert baseline == {resident: 50}, f"the group's starting membership was {baseline!r}, expected one endpoint at weight 50"

    # AddEndpoints refuses an EndpointId the group already holds.
    _DUPLICATE_ENDPOINT = ("InvalidArgumentException", f"Cannot update an existing endpoint: {resident}.")
    expect_error(
        lambda: _past_transaction(
            lambda: ga.add_endpoints(
                EndpointGroupArn=group_arn,
                EndpointConfigurations=[{"EndpointId": resident, "Weight": 9}],
            )
        ),
        *_DUPLICATE_ENDPOINT,
    )
    after_duplicate = _membership(ga, group_arn)
    assert after_duplicate == baseline, (
        f"a refused duplicate add changed the group's membership to {after_duplicate!r}, "
        f"expected it to stay {baseline!r}"
    )

    # Positive control: an id the group does not yet hold is accepted, proving the refusal above
    # was about the duplicate id, not about AddEndpoints itself.
    newcomer = ec2.allocate_address(Domain="vpc")["AllocationId"]
    ctx.on_cleanup(lambda: _release_quietly(ec2, newcomer))
    _past_transaction(
        lambda: ga.add_endpoints(
            EndpointGroupArn=group_arn,
            EndpointConfigurations=[{"EndpointId": newcomer, "Weight": 30}],
        )
    )
    after_add = _membership(ga, group_arn)
    assert after_add == {resident: 50, newcomer: 30}, (
        f"accepting a genuinely new endpoint left the group at {after_add!r}, "
        f"expected {{{resident!r}: 50, {newcomer!r}: 30}}"
    )

    # RemoveEndpoints no-ops on an id the group never held.
    stranger = ec2.allocate_address(Domain="vpc")["AllocationId"]
    ctx.on_cleanup(lambda: _release_quietly(ec2, stranger))
    _past_transaction(
        lambda: ga.remove_endpoints(
            EndpointGroupArn=group_arn, EndpointIdentifiers=[{"EndpointId": stranger}]
        )
    )
    after_absent_remove = _membership(ga, group_arn)
    assert after_absent_remove == after_add, (
        f"removing an id the group never held changed its membership to {after_absent_remove!r}, "
        f"expected it to stay {after_add!r}"
    )

    # Positive control: an id the group actually holds is removed for real, proving the no-op
    # above was about the absent id, not about RemoveEndpoints itself.
    _past_transaction(
        lambda: ga.remove_endpoints(
            EndpointGroupArn=group_arn, EndpointIdentifiers=[{"EndpointId": newcomer}]
        )
    )
    after_real_remove = _membership(ga, group_arn)
    assert after_real_remove == {resident: 50}, (
        f"removing an id the group actually held left membership at {after_real_remove!r}, "
        f"expected only {{{resident!r}: 50}}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
