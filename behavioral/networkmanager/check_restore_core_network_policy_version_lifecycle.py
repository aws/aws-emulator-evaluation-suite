"""restore-core-network-policy-version-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-core-network-policy-version-lifecycle"
GROUP = "core-network-policy"
SERVICES = ["networkmanager"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RestoreCoreNetworkPolicyVersion rejects restoring the version that is currently LIVE
    (real AWS answers ValidationException, not ConflictException) but restores an older one."""
    nm = ctx.client("networkmanager")
    gn_id = _create_global_network(ctx, nm)
    cn_id = _create_core_network(ctx, nm, gn_id)

    v1 = _put_and_execute(ctx, nm, cn_id, "segone")
    v2 = _put_and_execute(ctx, nm, cn_id, "segtwo")
    assert v2 == v1 + 1, f"expected the second executed policy version to be v1+1={v1 + 1}, got {v2}"

    live_before = nm.get_core_network_policy(CoreNetworkId=cn_id, Alias="LIVE")["CoreNetworkPolicy"]
    assert live_before["PolicyVersionId"] == v2, (
        f"expected LIVE alias to point at {v2} after executing it, got {live_before['PolicyVersionId']}"
    )

    # Break: restoring the version that is currently LIVE is rejected. Measured against real AWS:
    # the rejection is ValidationException, not ConflictException.
    code, message = _expect_rejected(lambda: nm.restore_core_network_policy_version(CoreNetworkId=cn_id, PolicyVersionId=v2))
    assert code == "ValidationException", f"expected ValidationException restoring currently-LIVE version {v2}, got {code!r}"
    expected_message = "Live policy cannot be restored."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no new version was created.
    versions_after_break = nm.list_core_network_policy_versions(CoreNetworkId=cn_id)["CoreNetworkPolicyVersions"]
    ids_after_break = {v["PolicyVersionId"] for v in versions_after_break}
    assert ids_after_break == {v1, v2}, f"expected only versions {{{v1}, {v2}}} to exist, got {ids_after_break}"

    # Positive control: restoring an older, non-LIVE version succeeds and creates a new LATEST.
    # `Alias` is modelled as optional on RestoreCoreNetworkPolicyVersion's own response and real
    # AWS leaves it unset there; the LATEST alias is confirmed via an independent read instead.
    restored = nm.restore_core_network_policy_version(CoreNetworkId=cn_id, PolicyVersionId=v1)["CoreNetworkPolicy"]
    v3 = restored["PolicyVersionId"]
    assert v3 == v2 + 1, f"expected the restore to mint version v2+1={v2 + 1}, got {v3}"

    latest_alias = nm.get_core_network_policy(CoreNetworkId=cn_id, Alias="LATEST")["CoreNetworkPolicy"]
    assert latest_alias["PolicyVersionId"] == v3, (
        f"expected LATEST alias to point at the restored version {v3}, got {latest_alias['PolicyVersionId']}"
    )

    latest = _poll_until(
        lambda: nm.get_core_network_policy(CoreNetworkId=cn_id, PolicyVersionId=v3)["CoreNetworkPolicy"],
        lambda p: p["ChangeSetState"] in ("READY_TO_EXECUTE", "FAILED_GENERATION"),
    )
    assert latest["ChangeSetState"] == "READY_TO_EXECUTE", (
        f"expected the restored version's change set to reach READY_TO_EXECUTE, got {latest['ChangeSetState']!r}"
    )
    segment_names = [s["name"] for s in json.loads(latest["PolicyDocument"])["segments"]]
    assert segment_names == ["segone"], (
        f"expected the restored version's document to be v1's (segments=['segone']), got {segment_names}"
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


def _expect_rejected(fn):
    """For a one-shot rejection assertion, where success is never valid."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
    gn_id = nm.create_global_network(
        Description=ctx.unique_name("sim2real-gn-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["GlobalNetwork"]["GlobalNetworkId"]
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
    cn_id = nm.create_core_network(
        GlobalNetworkId=gn_id,
        Description=ctx.unique_name("sim2real-cn-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["CoreNetwork"]["CoreNetworkId"]
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


def _live_version_id_or_none(nm, cn_id):
    # Before the FIRST ever change set finishes applying, there is no LIVE alias at all and
    # real AWS answers ValidationException("Policy not found") rather than a stale version --
    # that is "not ready yet", not a fatal error, so the poll must tolerate it.
    try:
        return nm.get_core_network_policy(CoreNetworkId=cn_id, Alias="LIVE")["CoreNetworkPolicy"]["PolicyVersionId"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ValidationException":
            return None
        raise


def _put_and_execute(ctx, nm, cn_id, segment_name):
    version_id = nm.put_core_network_policy(
        CoreNetworkId=cn_id, PolicyDocument=_minimal_policy(ctx, segment_name)
    )["CoreNetworkPolicy"]["PolicyVersionId"]
    _poll_until(
        lambda: nm.get_core_network_policy(CoreNetworkId=cn_id, PolicyVersionId=version_id)["CoreNetworkPolicy"][
            "ChangeSetState"
        ],
        lambda s: s == "READY_TO_EXECUTE",
    )
    nm.execute_core_network_change_set(CoreNetworkId=cn_id, PolicyVersionId=version_id)
    _poll_until(
        lambda: _live_version_id_or_none(nm, cn_id),
        lambda v: v == version_id,
        timeout_s=600.0,
        interval_s=10.0,
    )
    return version_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
