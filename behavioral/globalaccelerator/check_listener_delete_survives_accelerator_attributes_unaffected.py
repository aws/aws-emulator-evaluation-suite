"""listener-delete-survives-accelerator-attributes-unaffected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "listener-delete-survives-accelerator-attributes-unaffected"
GROUP = 'representation'
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


def _delete_accelerator_net(ga, arn):
    """Undo an accelerator completely: listeners, disable, delete."""
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
            ga.delete_listener(ListenerArn=listener["ListenerArn"])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "AcceleratorNotFoundException":
            raise
        return
    _retry(
        lambda: ga.delete_accelerator(AcceleratorArn=arn),
        codes=("AcceleratorNotDisabledException", "TransactionInProgressException"),
        budget_s=600.0,
    )


def _accelerator_arns(ga):
    arns, token = [], None
    while True:
        page = ga.list_accelerators(**({"NextToken": token} if token else {}))
        arns += [a["AcceleratorArn"] for a in page.get("Accelerators", [])]
        token = page.get("NextToken")
        if not token:
            return arns




@tags("axis:rejection", "concern:representation", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """A listener's ClientAffinity change and its eventual deletion never touch the
    accelerator's own attributes, and the accelerator keeps answering Describe normally
    after its only listener is gone and returns not-found.
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

    before_attrs = ga.describe_accelerator_attributes(AcceleratorArn=arn)["AcceleratorAttributes"]
    assert before_attrs == {"FlowLogsEnabled": False}, (
        f"a fresh accelerator's attributes are {before_attrs!r}, expected only "
        f"{{'FlowLogsEnabled': False}}"
    )

    present = _accelerator_arns(ga)
    assert arn in present, (
        f"a just-created accelerator with no listener at all is missing from ListAccelerators; "
        f"saw {present!r}"
    )

    listener = ga.create_listener(
        AcceleratorArn=arn,
        PortRanges=[{"FromPort": 80, "ToPort": 80}],
        Protocol="TCP",
        IdempotencyToken=str(uuid.uuid4()),
    )["Listener"]
    listener_arn = listener["ListenerArn"]
    assert listener["ClientAffinity"] == "NONE", (
        f"a listener created with no ClientAffinity reports {listener['ClientAffinity']!r}, "
        f"expected the documented default 'NONE'"
    )

    ga.update_listener(ListenerArn=listener_arn, ClientAffinity="SOURCE_IP")
    changed = ga.describe_listener(ListenerArn=listener_arn)["Listener"]
    assert changed["ClientAffinity"] == "SOURCE_IP", (
        f"after UpdateListener(ClientAffinity='SOURCE_IP'), DescribeListener reports "
        f"{changed['ClientAffinity']!r}"
    )

    after_attrs = ga.describe_accelerator_attributes(AcceleratorArn=arn)["AcceleratorAttributes"]
    assert after_attrs == before_attrs, (
        f"changing the listener's ClientAffinity changed the accelerator's own attributes from "
        f"{before_attrs!r} to {after_attrs!r}; listener state must not leak into accelerator "
        f"attributes"
    )

    # Positive control + relationship: deleting the listener is a no-op on the accelerator. The
    # listener itself becomes not-found while the accelerator keeps answering Describe normally
    # and its attributes are still exactly what they were before the listener ever existed.
    ga.delete_listener(ListenerArn=listener_arn)

    gone_code, gone_message = _error(lambda: ga.describe_listener(ListenerArn=listener_arn))
    assert gone_code == "ListenerNotFoundException", (
        f"after deleting the listener, DescribeListener returned {gone_code!r}, expected "
        f"'ListenerNotFoundException'"
    )
    expected_gone_message = f"Listener {listener_arn} not found."
    assert gone_message == expected_gone_message, (
        f"after deleting the listener, DescribeListener returned message {gone_message!r}, "
        f"expected {expected_gone_message!r}"
    )

    survived = ga.describe_accelerator(AcceleratorArn=arn)["Accelerator"]
    assert survived["AcceleratorArn"] == arn, (
        f"the accelerator did not survive its only listener's deletion: DescribeAccelerator "
        f"returned {survived!r}"
    )
    final_attrs = ga.describe_accelerator_attributes(AcceleratorArn=arn)["AcceleratorAttributes"]
    assert final_attrs == before_attrs, (
        f"after the listener was deleted, the accelerator's attributes are {final_attrs!r}, "
        f"expected them unchanged at {before_attrs!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
