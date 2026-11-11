"""accelerator-delete-rejects-enabled-accelerator."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "accelerator-delete-rejects-enabled-accelerator"
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
    """Undo an accelerator completely: disable, then delete once the disable has settled."""
    try:
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


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """DeleteAccelerator on an enabled accelerator fails with AcceleratorNotDisabledException and its exact message
    and leaves it enabled; once it is disabled the delete succeeds and DescribeAccelerator fails with
    AcceleratorNotFoundException 'Accelerator <arn> not found.'.
    """
    ga = ctx.client("globalaccelerator")

    accelerator = ga.create_accelerator(
        Name=ctx.unique_name("sim2real-behav-ga-"),
        IpAddressType="IPV4",
        Enabled=True,
        IdempotencyToken=str(uuid.uuid4()),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Accelerator"]
    arn = accelerator["AcceleratorArn"]
    ctx.on_cleanup(lambda: _delete_accelerator_net(ga, arn))
    assert accelerator["Enabled"] is True, (
        f"setup: the accelerator was created enabled but reports Enabled="
        f"{accelerator['Enabled']!r}"
    )

    code, message = _error(lambda: ga.delete_accelerator(AcceleratorArn=arn))
    assert code == "AcceleratorNotDisabledException", (
        f"DeleteAccelerator on an enabled accelerator returned {code!r}, expected "
        f"'AcceleratorNotDisabledException'"
    )
    expected = f"Please disable accelerator {arn} before deleting it."
    assert message == expected, (
        f"DeleteAccelerator on an enabled accelerator returned message {message!r}, expected "
        f"{expected!r}"
    )
    survived = ga.describe_accelerator(AcceleratorArn=arn)["Accelerator"]
    assert survived["Enabled"] is True, (
        f"the refused delete changed the accelerator: Enabled is now {survived['Enabled']!r}"
    )
    assert survived["AcceleratorArn"] == arn, (
        f"DescribeAccelerator returned {survived['AcceleratorArn']!r}, not the accelerator we "
        f"created"
    )

    # Positive control: the same DeleteAccelerator call succeeds on the same accelerator once it
    # is disabled, so the refusal above is the Enabled state and nothing else. The disable is not
    # synchronous, so the delete has to be retried through the same error.
    ga.update_accelerator(AcceleratorArn=arn, Enabled=False)
    _retry(
        lambda: ga.delete_accelerator(AcceleratorArn=arn),
        codes=("AcceleratorNotDisabledException", "TransactionInProgressException"),
        budget=600.0,
        delay=10.0,
    )
    gone, gone_message = _error(lambda: ga.describe_accelerator(AcceleratorArn=arn))
    assert gone == "AcceleratorNotFoundException", (
        f"after a successful delete, DescribeAccelerator returned {gone!r}, expected "
        f"'AcceleratorNotFoundException'"
    )
    assert gone_message == f"Accelerator {arn} not found.", (
        f"after a successful delete, DescribeAccelerator returned message {gone_message!r}, "
        f"expected {f'Accelerator {arn} not found.'!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
