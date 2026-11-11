"""hub-create-describe-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hub-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateHub creates a private hub that reaches HubStatus InService and is retrievable via
    DescribeHub, and DeleteHub removes it (subsequent DescribeHub returns ResourceNotFound)."""
    sm = ctx.client("sagemaker")
    hub_name = ctx.unique_name("sim2real-sm-hub-")

    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_hub(HubName=hub_name)))
    sm.create_hub(
        HubName=hub_name,
        HubDescription="sim2real behavioral check hub",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    desc = _poll_until(
        lambda: sm.describe_hub(HubName=hub_name),
        lambda d: d["HubStatus"] in ("InService", "CreateFailed"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert desc["HubStatus"] == "InService", f"expected InService, got {desc['HubStatus']!r}: {desc.get('FailureReason')}"
    assert desc["HubName"] == hub_name, f"expected HubName {hub_name!r}, got {desc['HubName']!r}"
    assert desc["HubDescription"] == "sim2real behavioral check hub", (
        f"expected the HubDescription we set, got {desc['HubDescription']!r}"
    )

    sm.delete_hub(HubName=hub_name)

    code, message = _poll_gone(lambda: sm.describe_hub(HubName=hub_name), timeout_s=60.0, interval_s=5.0)
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code!r}"
    assert message == f"Hub with name {hub_name} does not exist.", f"unexpected DescribeHub message: {message!r}"

    # a mutation on the dead id must also fail, not resurrect or silently no-op
    second_delete_code, second_delete_message = _error(lambda: sm.delete_hub(HubName=hub_name))
    assert second_delete_code == "ResourceNotFound", (
        f"expected a delete of an already-deleted hub to fail with ResourceNotFound, got {second_delete_code!r}"
    )
    assert second_delete_message == f"Hub with name {hub_name} does not exist.", (
        f"unexpected second DeleteHub message: {second_delete_message!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn):
    """The AWS (code, message) raised by fn(); an unexpected SUCCESS raises, so a target that
    accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _poll_gone(fn, *, timeout_s: float, interval_s: float):
    """Poll fn() until it is refused and return the refusal's (code, message); the delete is
    asynchronous, so a success inside the window is retried and one that outlasts it raises."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"the deleted resource was still readable after {timeout_s}s: {last!r}")


def _poll_until(probe, predicate, timeout_s: float = 120.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
