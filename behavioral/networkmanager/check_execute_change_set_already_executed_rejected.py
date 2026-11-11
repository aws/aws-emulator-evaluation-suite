"""execute-change-set-already-executed-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-change-set-already-executed-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmanager"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Executing an already-EXECUTION_SUCCEEDED change set a second time is rejected; a fresh
    version can still be executed afterward, so the rejection is specific to the stale version id
    and not a general lockup of ExecuteCoreNetworkChangeSet on this core network."""
    nm = ctx.client("networkmanager")
    gn_id = _create_global_network(ctx, nm)
    cn_id = _create_core_network(ctx, nm, gn_id)

    version_id = nm.put_core_network_policy(CoreNetworkId=cn_id, PolicyDocument=_minimal_policy(ctx, "segone"))[
        "CoreNetworkPolicy"
    ]["PolicyVersionId"]
    _poll_until(
        lambda: nm.get_core_network_policy(CoreNetworkId=cn_id, Alias="LATEST")["CoreNetworkPolicy"][
            "ChangeSetState"
        ],
        lambda s: s == "READY_TO_EXECUTE",
    )

    # Positive control: the first execution succeeds and reaches EXECUTION_SUCCEEDED. Poll the
    # change set by its own PolicyVersionId (always resolvable) rather than the LIVE alias: the
    # alias does not exist until the first-ever execution commits, and answers
    # ValidationException("Policy not found") for a while after that, so it lags the change set's
    # own state.
    nm.execute_core_network_change_set(CoreNetworkId=cn_id, PolicyVersionId=version_id)
    _poll_until(
        lambda: nm.get_core_network_policy(CoreNetworkId=cn_id, PolicyVersionId=version_id)["CoreNetworkPolicy"][
            "ChangeSetState"
        ],
        lambda s: s == "EXECUTION_SUCCEEDED",
        timeout_s=1500.0,
        interval_s=10.0,
    )
    live = _poll_until(
        lambda: _live_policy_or_none(nm, cn_id),
        lambda p: p is not None and p["ChangeSetState"] == "EXECUTION_SUCCEEDED",
        timeout_s=30.0,
    )
    assert live["PolicyVersionId"] == version_id, (
        f"expected LIVE to be version_id={version_id} after the first execution, got "
        f"{live['PolicyVersionId']!r}"
    )

    # Break: executing the same, already-executed change set again is rejected. Real AWS answers
    # ValidationException("Change set state for policy is invalid."), not a ConflictException --
    # the change set's own state (not a concurrent write) is what makes the re-execution invalid.
    error = _expect_error(
        lambda: nm.execute_core_network_change_set(CoreNetworkId=cn_id, PolicyVersionId=version_id)
    )
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException re-executing already-EXECUTION_SUCCEEDED version_id="
        f"{version_id}, got {error['Code']!r}"
    )
    assert error["Message"] == "Change set state for policy is invalid.", (
        f"expected message 'Change set state for policy is invalid.' re-executing "
        f"already-EXECUTION_SUCCEEDED version_id={version_id}, got {error['Message']!r}"
    )

    # Effect absent: the LIVE policy is unchanged (still v1, still EXECUTION_SUCCEEDED, not duplicated).
    live_after = nm.get_core_network_policy(CoreNetworkId=cn_id, Alias="LIVE")["CoreNetworkPolicy"]
    assert live_after["PolicyVersionId"] == version_id, (
        f"expected LIVE to remain version_id={version_id} after the rejected re-execution, got "
        f"{live_after['PolicyVersionId']!r}"
    )
    assert live_after["ChangeSetState"] == "EXECUTION_SUCCEEDED", (
        f"expected LIVE ChangeSetState to remain EXECUTION_SUCCEEDED after the rejected "
        f"re-execution, got {live_after['ChangeSetState']!r}"
    )

    # Positive control after the rejection: the same version id can never re-execute by
    # construction (EXECUTION_SUCCEEDED is terminal), so the analogous proof that the mechanism
    # itself is not broadly wedged is a fresh version executing successfully.
    version2_id = nm.put_core_network_policy(CoreNetworkId=cn_id, PolicyDocument=_minimal_policy(ctx, "segtwo"))[
        "CoreNetworkPolicy"
    ]["PolicyVersionId"]
    _poll_until(
        lambda: nm.get_core_network_policy(CoreNetworkId=cn_id, PolicyVersionId=version2_id)["CoreNetworkPolicy"][
            "ChangeSetState"
        ],
        lambda s: s == "READY_TO_EXECUTE",
    )
    nm.execute_core_network_change_set(CoreNetworkId=cn_id, PolicyVersionId=version2_id)
    live_after_v2 = _poll_until(
        lambda: _live_policy_or_none(nm, cn_id),
        lambda p: p is not None
        and p["PolicyVersionId"] == version2_id
        and p["ChangeSetState"] == "EXECUTION_SUCCEEDED",
        timeout_s=1500.0,
        interval_s=10.0,
    )
    assert live_after_v2["PolicyVersionId"] == version2_id, (
        f"expected LIVE to move to the fresh version2_id={version2_id} after its execution, got "
        f"{live_after_v2['PolicyVersionId']!r}"
    )


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _is_gone(fn):
    """True once fn() is refused with ResourceNotFoundException or answers an empty list (polling only)."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"] == "ResourceNotFoundException"
    return result == []


def _expect_error(fn):
    """Return the Error dict of a refused call; an unexpected SUCCESS raises rather than returning a
    falsy sentinel. Returns the full Error dict (Code + Message)."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _live_policy_or_none(nm, cn_id):
    try:
        return nm.get_core_network_policy(CoreNetworkId=cn_id, Alias="LIVE")["CoreNetworkPolicy"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ValidationException":
            return None
        raise


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
    # DeleteGlobalNetwork is refused while its core network is still deleting (several minutes
    # once a policy has been executed), so the delete is retried on every poll.
    def _delete_and_check():
        _safe_call(lambda: nm.delete_global_network(GlobalNetworkId=gn_id))
        return _is_gone(lambda: nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"])

    _poll_until(_delete_and_check, lambda gone: gone, timeout_s=900.0, interval_s=10.0)


def _create_core_network(ctx, nm, gn_id):
    cn_id = nm.create_core_network(GlobalNetworkId=gn_id, Description=ctx.unique_name("sim2real-cn-"))[
        "CoreNetwork"
    ]["CoreNetworkId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: nm.delete_core_network(CoreNetworkId=cn_id)))
    _poll_until(
        lambda: nm.get_core_network(CoreNetworkId=cn_id)["CoreNetwork"]["State"],
        lambda s: s == "AVAILABLE",
    )
    return cn_id


def _minimal_policy(ctx, segment_name):
    return json.dumps(
        {
            "version": "2021.12",
            "core-network-configuration": {
                "asn-ranges": ["64512-65534"],
                "edge-locations": [{"location": ctx.region}],
            },
            "segments": [{"name": segment_name, "require-attachment-acceptance": False}],
            "attachment-policies": [
                {
                    "rule-number": 100,
                    "condition-logic": "and",
                    "conditions": [{"type": "any"}],
                    "action": {"association-method": "constant", "segment": segment_name},
                }
            ],
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
