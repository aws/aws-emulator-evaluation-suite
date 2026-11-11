"""put-core-network-policy-optimistic-lock-concurrent."""
from __future__ import annotations

import concurrent.futures as cf
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-core-network-policy-optimistic-lock-concurrent"
GROUP = "core-network-policy"
SERVICES = ["networkmanager"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutCoreNetworkPolicy calls with the same LatestVersionId: exactly one wins."""
    nm = ctx.client("networkmanager")
    gn_id = _create_global_network(ctx, nm)
    cn_id = _create_core_network(ctx, nm, gn_id)

    v1 = nm.put_core_network_policy(CoreNetworkId=cn_id, PolicyDocument=_minimal_policy(ctx, "segbase"))[
        "CoreNetworkPolicy"
    ]["PolicyVersionId"]
    _poll_until(
        lambda: nm.get_core_network_policy(CoreNetworkId=cn_id, Alias="LATEST")["CoreNetworkPolicy"][
            "ChangeSetState"
        ],
        lambda s: s in ("READY_TO_EXECUTE", "FAILED_GENERATION"),
    )

    def _racer(segment_name):
        try:
            resp = nm.put_core_network_policy(
                CoreNetworkId=cn_id,
                PolicyDocument=_minimal_policy(ctx, segment_name),
                LatestVersionId=v1,
            )
            return (segment_name, "ok", resp["CoreNetworkPolicy"]["PolicyVersionId"], None)
        except ClientError as e:
            return (segment_name, "error", e.response["Error"]["Code"], e.response["Error"]["Message"])

    with cf.ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(_racer, name) for name in ("segracera", "segracerb")]
        results = [f.result() for f in futures]

    oks = [r for r in results if r[1] == "ok"]
    errors = [r for r in results if r[1] == "error"]
    assert len(oks) == 1, f"expected exactly one winner among racers, got {results}"
    assert len(errors) == 1, f"expected exactly one loser among racers, got {results}"
    # Real AWS rejects a stale LatestVersionId with ValidationException, not ConflictException —
    # confirmed against real AWS; do not revert this to ConflictException without re-confirming.
    assert errors[0][2] == "ValidationException", f"expected ValidationException for the loser, got {results}"
    assert errors[0][3] == "Invalid input. Invalid latest version ID.", (
        f"expected the ValidationException message to reference the stale version, got {results}"
    )
    assert oks[0][2] == v1 + 1, f"expected the winner's PolicyVersionId to be v1+1={v1 + 1}, got {results}"

    # Independent read at the destination — a different operation than the racing PutCoreNetworkPolicy
    # calls — confirms which racer's content actually landed, not just which response looked like a win.
    winner_segment, _, winner_version, _ = oks[0]
    latest = nm.get_core_network_policy(CoreNetworkId=cn_id, Alias="LATEST")["CoreNetworkPolicy"]
    assert latest["PolicyVersionId"] == winner_version, (
        f"expected LATEST to point at the winning version {winner_version}, got {latest['PolicyVersionId']}"
    )
    committed = json.loads(
        nm.get_core_network_policy(CoreNetworkId=cn_id, PolicyVersionId=winner_version)["CoreNetworkPolicy"][
            "PolicyDocument"
        ]
    )
    committed_segment = committed["segments"][0]["name"]
    assert committed_segment == winner_segment, (
        f"expected the committed policy to carry the winning racer's segment {winner_segment!r}, "
        f"got {committed_segment!r}"
    )

    versions = {
        v["PolicyVersionId"]
        for v in nm.list_core_network_policy_versions(CoreNetworkId=cn_id)["CoreNetworkPolicyVersions"]
    }
    assert versions == {v1, winner_version}, (
        f"expected exactly versions {{{v1}, {winner_version}}} to exist, got {versions}"
    )


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["GlobalNetwork"]["GlobalNetworkId"]
    ctx.on_cleanup(lambda: _delete_global_network_and_wait(nm, gn_id))
    _poll_until(
        lambda: nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    return gn_id


# DeleteGlobalNetwork's refusal while its core network is still deleting.
_GN_IN_USE = "Global Network cannot be deleted due to an existing core network associated with it."
# One deadline shared by the check's teardowns.
_CLEANUP_S = 900.0
_DEADLINES: dict = {}


def _cleanup_deadline(client) -> float:
    held = _DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _DEADLINES[id(client)] = (client, time.monotonic() + _CLEANUP_S)
    return held[1]


def _delete_core_network_and_wait(nm, cn_id):
    """Teardown: delete the core network and wait until GetCoreNetwork answers
    ResourceNotFoundException; its global network cannot be deleted before that."""
    deadline = _cleanup_deadline(nm)
    _safe_call(lambda: nm.delete_core_network(CoreNetworkId=cn_id))
    while True:
        try:
            state = nm.get_core_network(CoreNetworkId=cn_id)["CoreNetwork"]["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"core network {cn_id} still {state!r} at the cleanup deadline")
        time.sleep(2)


def _delete_global_network_and_wait(nm, gn_id):
    """Teardown: delete the global network, retrying the in-use refusal, then wait until
    DescribeGlobalNetworks lists it no more (it answers an empty list for a deleted id)."""
    deadline = _cleanup_deadline(nm)
    while True:
        try:
            nm.delete_global_network(GlobalNetworkId=gn_id)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ResourceNotFoundException":
                return
            if (err["Code"] != "ValidationException" or err.get("Message") != _GN_IN_USE
                    or time.monotonic() >= deadline):
                raise
        time.sleep(2)
    while nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"]:
        if time.monotonic() >= deadline:
            raise AssertionError(f"global network {gn_id} still listed at the cleanup deadline")
        time.sleep(2)


def _create_core_network(ctx, nm, gn_id):
    cn_id = nm.create_core_network(
        GlobalNetworkId=gn_id,
        Description=ctx.unique_name("sim2real-cn-"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["CoreNetwork"]["CoreNetworkId"]
    ctx.on_cleanup(lambda: _delete_core_network_and_wait(nm, cn_id))
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
