"""delete-global-network-blocked-until-core-network-removed."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-global-network-blocked-until-core-network-removed"
GROUP = "state-machine"
SERVICES = ["networkmanager"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteGlobalNetwork is rejected while a core network still exists, and succeeds once removed."""
    nm = ctx.client("networkmanager")
    gn_id = _create_global_network(ctx, nm)
    cn_id = nm.create_core_network(GlobalNetworkId=gn_id, Description=ctx.unique_name("sim2real-cn-"))[
        "CoreNetwork"
    ]["CoreNetworkId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: nm.delete_core_network(CoreNetworkId=cn_id)))
    _poll_until(
        lambda: nm.get_core_network(CoreNetworkId=cn_id)["CoreNetwork"]["State"],
        lambda s: s == "AVAILABLE",
    )

    # Break: deleting the global network while its core network still exists is rejected.
    code, message = _error_code(lambda: nm.delete_global_network(GlobalNetworkId=gn_id))
    assert code == "ValidationException", f"actual code: {code!r}"
    expected_message = "Global Network cannot be deleted due to an existing core network associated with it."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the global network is still present and AVAILABLE.
    still_there = nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"][0]
    assert still_there["State"] == "AVAILABLE"

    # Restore: once the core network is actually gone, the identical DeleteGlobalNetwork call
    # now succeeds.
    nm.delete_core_network(CoreNetworkId=cn_id)
    _poll_until(
        lambda: _is_gone(lambda: nm.get_core_network(CoreNetworkId=cn_id)),
        lambda gone: gone,
        timeout_s=110.0,
    )
    core_gone_code, core_gone_message = _error_code(lambda: nm.get_core_network(CoreNetworkId=cn_id))
    assert core_gone_code == "ResourceNotFoundException", f"actual code: {core_gone_code!r}"
    expected_gone_message = "Resource not found."
    assert core_gone_message == expected_gone_message, (
        f"expected message {expected_gone_message!r}, got {core_gone_message!r}"
    )

    # The identical call now succeeds -- no ValidationException.
    nm.delete_global_network(GlobalNetworkId=gn_id)

    # Independent read: the global network passes through DELETING and is then gone.
    after_states = _poll_until(
        lambda: _gn_states(nm, gn_id),
        lambda states: states == [],
        timeout_s=40.0,
    )
    assert after_states == [], f"actual: {after_states!r}"

def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _is_gone(fn):
    """True once fn() is refused with ResourceNotFoundException or answers an empty list (polling only)."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"] == "ResourceNotFoundException"
    return result == []


def _gn_states(nm, gn_id):
    """The states DescribeGlobalNetworks reports for gn_id, [] once it is gone: AWS answers a
    deleted id with either an empty list or ResourceNotFoundException 'Resource not found.'."""
    try:
        networks = nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"]
    except ClientError as e:
        error = e.response["Error"]
        if error["Code"] == "ResourceNotFoundException" and error.get("Message") == "Resource not found.":
            return []
        raise
    return [n["State"] for n in networks]


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_global_network(ctx, nm):
    gn_id = nm.create_global_network(Description=ctx.unique_name("sim2real-gn-"))["GlobalNetwork"]["GlobalNetworkId"]
    ctx.on_cleanup(lambda: _delete_global_network_and_wait(nm, gn_id))
    _poll_until(
        lambda: nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    return gn_id


def _delete_global_network_and_wait(nm, gn_id):
    _safe_call(lambda: nm.delete_global_network(GlobalNetworkId=gn_id))
    _poll_until(
        lambda: _is_gone(lambda: nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"]),
        lambda gone: gone,
        timeout_s=150.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
