"""custom-routing-listener-delete-rejects-associated-endpoint-group."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-routing-listener-delete-rejects-associated-endpoint-group"
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


def _retry(fn, codes, budget_s=600.0, delay_s=10.0):
    """Call fn() until it stops raising one of `codes`; re-raise anything else."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in codes or time.monotonic() > deadline:
                raise
            time.sleep(delay_s)


def _delete_custom_routing_accelerator_net(ga, arn):
    """Undo a custom routing accelerator completely: listeners, endpoint groups, delete."""
    try:
        listeners = []
        token = None
        while True:
            page = ga.list_custom_routing_listeners(
                AcceleratorArn=arn, **({"NextToken": token} if token else {})
            )
            listeners += page.get("Listeners", [])
            token = page.get("NextToken")
            if not token:
                break
        for listener in listeners:
            for group in _groups_of(ga, listener["ListenerArn"]):
                ga.delete_custom_routing_endpoint_group(
                    EndpointGroupArn=group["EndpointGroupArn"]
                )
            ga.delete_custom_routing_listener(ListenerArn=listener["ListenerArn"])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "AcceleratorNotFoundException":
            raise
        return
    _retry(
        lambda: ga.delete_custom_routing_accelerator(AcceleratorArn=arn),
        codes=("AcceleratorNotDisabledException", "TransactionInProgressException"),
        budget_s=600.0,
    )


def _groups_of(ga, listener):
    groups, token = [], None
    while True:
        page = ga.list_custom_routing_endpoint_groups(
            ListenerArn=listener, **({"NextToken": token} if token else {})
        )
        groups += page.get("EndpointGroups", [])
        token = page.get("NextToken")
        if not token:
            return groups




@tags("axis:rejection", "concern:negative-classes", "concern:representation", "plane:control", "cap:c1")
def run(ctx) -> None:
    """DeleteCustomRoutingListener refuses a listener with an associated endpoint group, leaves
    the listener and accelerator intact, and only succeeds once the endpoint group is gone --
    after which the accelerator itself still answers Describe while the listener does not.
    """
    ga = ctx.client("globalaccelerator")

    accelerator = ga.create_custom_routing_accelerator(
        Name=ctx.unique_name("sim2real-behav-gacr-"),
        Enabled=False,
        IdempotencyToken=str(uuid.uuid4()),
    )["Accelerator"]
    arn = accelerator["AcceleratorArn"]
    ctx.on_cleanup(lambda: _delete_custom_routing_accelerator_net(ga, arn))

    listener = ga.create_custom_routing_listener(
        AcceleratorArn=arn,
        PortRanges=[{"FromPort": 1024, "ToPort": 65535}],
        IdempotencyToken=str(uuid.uuid4()),
    )["Listener"]["ListenerArn"]

    endpoint_group = ga.create_custom_routing_endpoint_group(
        ListenerArn=listener,
        EndpointGroupRegion=ctx.region,
        DestinationConfigurations=[{"FromPort": 80, "ToPort": 80, "Protocols": ["TCP"]}],
        IdempotencyToken=str(uuid.uuid4()),
    )["EndpointGroup"]["EndpointGroupArn"]

    described_accelerator = ga.describe_custom_routing_accelerator(AcceleratorArn=arn)[
        "Accelerator"
    ]
    assert described_accelerator["AcceleratorArn"] == arn, (
        f"DescribeCustomRoutingAccelerator returned {described_accelerator['AcceleratorArn']!r}, "
        f"not the accelerator we created"
    )
    attributes = ga.describe_custom_routing_accelerator_attributes(AcceleratorArn=arn)[
        "AcceleratorAttributes"
    ]
    assert attributes["FlowLogsEnabled"] is False, (
        f"a fresh custom routing accelerator reports FlowLogsEnabled="
        f"{attributes['FlowLogsEnabled']!r}, expected False"
    )
    described_listener = ga.describe_custom_routing_listener(ListenerArn=listener)["Listener"]
    assert described_listener["ListenerArn"] == listener, (
        f"DescribeCustomRoutingListener returned {described_listener['ListenerArn']!r}, not the "
        f"listener we created"
    )
    described_group = ga.describe_custom_routing_endpoint_group(
        EndpointGroupArn=endpoint_group
    )["EndpointGroup"]
    assert described_group["EndpointGroupArn"] == endpoint_group, (
        f"DescribeCustomRoutingEndpointGroup returned {described_group['EndpointGroupArn']!r}, "
        f"not the endpoint group we created"
    )

    code, message = _error(lambda: ga.delete_custom_routing_listener(ListenerArn=listener))
    assert code == "AssociatedEndpointGroupFoundException", (
        f"deleting a listener with an associated endpoint group returned {code!r}, expected "
        f"'AssociatedEndpointGroupFoundException'"
    )
    expected_message = f"Cannot delete listener {listener} because an associated endpoint group was found."
    assert message == expected_message, (
        f"deleting a listener with an associated endpoint group returned message {message!r}, "
        f"expected {expected_message!r}"
    )
    survived = ga.describe_custom_routing_listener(ListenerArn=listener)["Listener"]
    assert survived["ListenerArn"] == listener, (
        f"the refused delete changed the listener: DescribeCustomRoutingListener now returns "
        f"{survived['ListenerArn']!r}"
    )
    after_refusal = [g["EndpointGroupArn"] for g in _groups_of(ga, listener)]
    assert after_refusal == [endpoint_group], (
        f"after the refused delete, the listener holds {after_refusal!r}, expected only "
        f"{[endpoint_group]!r}"
    )

    # Positive control: the same DeleteCustomRoutingListener call succeeds on the same listener
    # once its endpoint group is gone, so the refusal above was the association and nothing else.
    # The accelerator itself persists past the listener's own deletion.
    ga.delete_custom_routing_endpoint_group(EndpointGroupArn=endpoint_group)
    ga.delete_custom_routing_listener(ListenerArn=listener)

    gone_code, gone_message = _error(
        lambda: ga.describe_custom_routing_listener(ListenerArn=listener)
    )
    assert gone_code == "ListenerNotFoundException", (
        f"after a successful delete, DescribeCustomRoutingListener returned {gone_code!r}, "
        f"expected 'ListenerNotFoundException'"
    )
    expected_gone_message = f"Listener {listener} not found."
    assert gone_message == expected_gone_message, (
        f"after a successful delete, DescribeCustomRoutingListener returned message "
        f"{gone_message!r}, expected {expected_gone_message!r}"
    )
    still_there = ga.describe_custom_routing_accelerator(AcceleratorArn=arn)["Accelerator"]
    assert still_there["AcceleratorArn"] == arn, (
        f"the accelerator did not survive its last listener's deletion: "
        f"DescribeCustomRoutingAccelerator returned {still_there!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
