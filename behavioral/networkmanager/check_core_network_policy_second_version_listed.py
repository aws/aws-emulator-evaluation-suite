"""core-network-policy-second-version-listed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "core-network-policy-second-version-listed"
GROUP = "core-network-policy"
SERVICES = ["networkmanager"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After executing v1 to LIVE and submitting v2, ListCoreNetworkPolicyVersions shows both aliases."""
    nm = ctx.client("networkmanager")
    gn_id = _create_global_network(ctx, nm)
    cn_id = _create_core_network(ctx, nm, gn_id)

    v1 = nm.put_core_network_policy(CoreNetworkId=cn_id, PolicyDocument=_minimal_policy(ctx, "segone"))[
        "CoreNetworkPolicy"
    ]["PolicyVersionId"]
    _poll_until(
        lambda: nm.get_core_network_policy(CoreNetworkId=cn_id, Alias="LATEST")["CoreNetworkPolicy"][
            "ChangeSetState"
        ],
        lambda s: s == "READY_TO_EXECUTE",
    )
    nm.execute_core_network_change_set(CoreNetworkId=cn_id, PolicyVersionId=v1)
    # The FIRST execution of a core network change set does not
    # merely flip a status field — it provisions the Cloud WAN segments/edges the policy declares,
    # and GetCoreNetworkPolicy(Alias="LIVE") answers ValidationException("Policy not found") for the
    # entire duration, not just a brief propagation window. 120s undershoots this badly.
    _poll_until(
        lambda: _alias_state_tolerating_propagation_delay(nm, cn_id, "LIVE"),
        lambda s: s == "EXECUTION_SUCCEEDED",
        timeout_s=1500.0,
        interval_s=15.0,
    )

    v2 = nm.put_core_network_policy(CoreNetworkId=cn_id, PolicyDocument=_minimal_policy(ctx, "segtwo"))[
        "CoreNetworkPolicy"
    ]["PolicyVersionId"]
    assert v2 == v1 + 1, f"expected the second policy version to be v1+1={v1 + 1}, got {v2}"
    _poll_until(
        lambda: nm.get_core_network_policy(CoreNetworkId=cn_id, Alias="LATEST")["CoreNetworkPolicy"][
            "ChangeSetState"
        ],
        lambda s: s == "READY_TO_EXECUTE",
    )

    versions = nm.list_core_network_policy_versions(CoreNetworkId=cn_id)["CoreNetworkPolicyVersions"]
    by_id = {v["PolicyVersionId"]: v for v in versions}
    assert by_id[v1]["Alias"] == "LIVE", f"expected v1={v1} aliased LIVE, got {by_id[v1]['Alias']!r}"
    assert by_id[v2]["Alias"] == "LATEST", f"expected v2={v2} aliased LATEST, got {by_id[v2]['Alias']!r}"
    assert by_id[v2]["ChangeSetState"] == "READY_TO_EXECUTE", (
        f"expected v2={v2} ChangeSetState READY_TO_EXECUTE, got {by_id[v2]['ChangeSetState']!r}"
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


def _alias_state_tolerating_propagation_delay(nm, cn_id, alias):
    # Right after the FIRST ExecuteCoreNetworkChangeSet, the LIVE alias record does not exist yet
    # for a brief window; GetCoreNetworkPolicy(Alias="LIVE") answers ValidationException("Policy not
    # found") rather than a pending ChangeSetState. Treat that as "not ready" so the poll keeps
    # waiting instead of crashing on a transient read.
    try:
        return nm.get_core_network_policy(CoreNetworkId=cn_id, Alias=alias)["CoreNetworkPolicy"][
            "ChangeSetState"
        ]
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")
        if code == "ValidationException" and "not found" in message.lower():
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
    gn_id = nm.create_global_network(
        Description=ctx.unique_name("sim2real-gn-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
