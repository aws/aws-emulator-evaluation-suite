"""core-network-policy-create-execute-reaches-live."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "core-network-policy-create-execute-reaches-live"
GROUP = "core-network-policy"
SERVICES = ["networkmanager"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutCoreNetworkPolicy -> ExecuteCoreNetworkChangeSet promotes a policy version to LIVE."""
    nm = ctx.client("networkmanager")
    gn_id = _create_global_network(ctx, nm)
    cn_id = _create_core_network(ctx, nm, gn_id)

    policy_doc = _minimal_policy(ctx, "segone")
    put = nm.put_core_network_policy(CoreNetworkId=cn_id, PolicyDocument=policy_doc)["CoreNetworkPolicy"]
    version_id = put["PolicyVersionId"]
    latest = nm.get_core_network_policy(CoreNetworkId=cn_id, Alias="LATEST")["CoreNetworkPolicy"]
    assert latest["Alias"] == "LATEST", f"expected GetCoreNetworkPolicy(Alias=LATEST) to echo LATEST, got {latest['Alias']!r}"
    assert latest["PolicyVersionId"] == version_id, (
        f"expected the just-put version {version_id} to be LATEST, got {latest['PolicyVersionId']}"
    )

    ready = _poll_until(
        lambda: nm.get_core_network_policy(CoreNetworkId=cn_id, Alias="LATEST")["CoreNetworkPolicy"][
            "ChangeSetState"
        ],
        lambda s: s in ("READY_TO_EXECUTE", "FAILED_GENERATION"),
    )
    assert ready == "READY_TO_EXECUTE", f"expected policy change set READY_TO_EXECUTE, got {ready}"

    nm.execute_core_network_change_set(CoreNetworkId=cn_id, PolicyVersionId=version_id)

    # GetCoreNetworkPolicy(Alias="LIVE") throws ValidationException "Policy not found" for as
    # long as ~250-300s while the change set is genuinely still executing,
    # so poll by PolicyVersionId instead, which is valid immediately after execute.
    live = _poll_until(
        lambda: nm.get_core_network_policy(CoreNetworkId=cn_id, PolicyVersionId=version_id)["CoreNetworkPolicy"],
        lambda p: p["ChangeSetState"] in ("EXECUTION_SUCCEEDED", "EXECUTION_FAILED"),
        timeout_s=1500.0,
        interval_s=10.0,
    )
    assert live["ChangeSetState"] == "EXECUTION_SUCCEEDED", (
        f"expected change set EXECUTION_SUCCEEDED, got {live['ChangeSetState']}"
    )
    assert live["PolicyVersionId"] == version_id, (
        f"expected the executed version to remain {version_id}, got {live['PolicyVersionId']}"
    )
    # A version that is simultaneously LIVE and LATEST (true here: it is the only version ever
    # put) reports Alias as the combined string "LIVE, LATEST", not a bare "LIVE".
    assert "LIVE" in live["Alias"].split(", "), f"expected version {version_id} promoted to LIVE, got Alias={live['Alias']!r}"
    live_doc = json.loads(live["PolicyDocument"])
    segment_names = [s["name"] for s in live_doc["segments"]]
    assert "segone" in segment_names, f"expected segment 'segone' in live policy, got {segment_names}"


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
        Tags=[{"Key": "sim2real-team", "Value": "net-eng"}],
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
        Tags=[{"Key": "sim2real-team", "Value": "net-eng"}],
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
