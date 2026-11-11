"""global-network-lifecycle-delete-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-network-lifecycle-delete-transition"
GROUP = "state-machine"
SERVICES = ["networkmanager"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGlobalNetwork transitions to AVAILABLE and DeleteGlobalNetwork fully removes it."""
    nm = ctx.client("networkmanager")
    desc = ctx.unique_name("sim2real-gn-")
    created = nm.create_global_network(
        Description=desc,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["GlobalNetwork"]
    gn_id = created["GlobalNetworkId"]
    assert created["State"] in ("PENDING", "AVAILABLE"), f"unexpected initial state: {created['State']!r}"

    def _cleanup():
        try:
            nm.delete_global_network(GlobalNetworkId=gn_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    state = _poll_until(
        lambda: nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    assert state == "AVAILABLE", f"expected AVAILABLE, got {state!r}"

    nm.delete_global_network(GlobalNetworkId=gn_id)

    remaining = _poll_until(
        lambda: nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"],
        lambda gns: gns == [],
        timeout_s=180.0,
    )
    assert remaining == [], f"expected no global networks with id {gn_id!r} after delete, got {remaining!r}"

    # A mutation on the now-deleted id must also fail -- gone means unusable, not just unlisted.
    update_code, update_message = _error_code(lambda: nm.update_global_network(GlobalNetworkId=gn_id, Description="post-delete"))
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateGlobalNetwork on deleted id to fail with ResourceNotFoundException, got {update_code!r}"
    )
    expected_message = "Resource not found."
    assert update_message == expected_message, f"expected message {expected_message!r}, got {update_message!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
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
