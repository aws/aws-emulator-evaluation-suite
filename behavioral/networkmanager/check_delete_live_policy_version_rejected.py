"""delete-live-policy-version-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-live-policy-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmanager"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCoreNetworkPolicyVersion rejects the current LIVE version. Once a newer
    version is promoted to LIVE and demotes it, the identical delete call succeeds."""
    nm = ctx.client("networkmanager")

    def _core_network_gone(cn_id):
        try:
            nm.get_core_network(CoreNetworkId=cn_id)
            return False
        except ClientError as e:
            return e.response["Error"]["Code"] == "ResourceNotFoundException"

    gn_id = _create_global_network(ctx, nm)
    cn_id = _create_core_network(ctx, nm, gn_id)

    v1 = _put_and_execute(ctx, nm, cn_id, "segone")

    # Positive control: a version that was never LIVE can be deleted outright.
    v_draft = nm.put_core_network_policy(CoreNetworkId=cn_id, PolicyDocument=_minimal_policy(ctx, "segtwo"))[
        "CoreNetworkPolicy"
    ]["PolicyVersionId"]
    assert v_draft == v1 + 1, f"expected sequential version id {v1 + 1}, got {v_draft}"
    _poll_until(
        lambda: nm.get_core_network_policy(CoreNetworkId=cn_id, Alias="LATEST")["CoreNetworkPolicy"][
            "ChangeSetState"
        ],
        lambda s: s == "READY_TO_EXECUTE",
    )
    nm.delete_core_network_policy_version(CoreNetworkId=cn_id, PolicyVersionId=v_draft)
    ids_after_control = _list_version_ids(nm, cn_id)
    assert v_draft not in ids_after_control, "positive control: never-LIVE draft must be deletable"
    assert v1 in ids_after_control, "deleting the draft must not disturb the LIVE version"

    # Break: deleting the current LIVE version is rejected.
    try:
        nm.delete_core_network_policy_version(CoreNetworkId=cn_id, PolicyVersionId=v1)
    except ClientError as e:
        code, message = e.response["Error"]["Code"], e.response["Error"]["Message"]
    else:
        raise AssertionError("expected deleting the current LIVE policy version to be rejected, but it succeeded")
    assert code == "ValidationException", f"expected ValidationException deleting LIVE version, got {code!r}: {message!r}"
    assert message == "Cannot delete the live version of the core network ID.", (
        f"expected a live-version refusal, got {code!r}: {message!r}"
    )

    # Effect absent: v1 is still listed.
    ids_after_break = _list_version_ids(nm, cn_id)
    assert v1 in ids_after_break, "LIVE version must survive the rejected delete"

    # Restore: promote a newer version to LIVE, demoting v1 from LIVE.
    v3 = _put_and_execute(ctx, nm, cn_id, "segthree")

    # Identical call now succeeds: the same v1 that was rejected as LIVE is deletable
    # once demoted -- proving the rejection tracked LIVE status, not the version itself.
    nm.delete_core_network_policy_version(CoreNetworkId=cn_id, PolicyVersionId=v1)
    ids_after_restore = _list_version_ids(nm, cn_id)
    assert v1 not in ids_after_restore, "v1 must become deletable once demoted from LIVE"
    assert v3 in ids_after_restore, "the newly-promoted LIVE version must survive v1's delete"


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0, tolerate_not_found=False):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except ClientError as e:
            # Right after ExecuteCoreNetworkChangeSet promotes the very first version, the
            # LIVE alias briefly 404s (ValidationException, not a pending state) before it
            # resolves -- confirmed against real AWS, not assumed. Treat that as not-ready-yet.
            if tolerate_not_found and e.response["Error"]["Code"] == "ValidationException" and "not found" in str(e).lower():
                time.sleep(interval_s)
                continue
            raise
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


# DeleteGlobalNetwork's refusal while its core network is still deleting.
_GN_IN_USE = "Global Network cannot be deleted due to an existing core network associated with it."
# One 900 s deadline shared by this check's teardowns (core-network deletion after an executed policy takes several minutes).
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
    cn_id = nm.create_core_network(GlobalNetworkId=gn_id, Description=ctx.unique_name("sim2real-cn-"))[
        "CoreNetwork"
    ]["CoreNetworkId"]
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


def _put_and_execute(ctx, nm, cn_id, segment_name):
    version_id = nm.put_core_network_policy(CoreNetworkId=cn_id, PolicyDocument=_minimal_policy(ctx, segment_name))[
        "CoreNetworkPolicy"
    ]["PolicyVersionId"]
    _poll_until(
        lambda: nm.get_core_network_policy(CoreNetworkId=cn_id, Alias="LATEST")["CoreNetworkPolicy"][
            "ChangeSetState"
        ],
        lambda s: s == "READY_TO_EXECUTE",
    )
    nm.execute_core_network_change_set(CoreNetworkId=cn_id, PolicyVersionId=version_id)
    _poll_until(
        lambda: nm.get_core_network_policy(CoreNetworkId=cn_id, Alias="LIVE")["CoreNetworkPolicy"][
            "PolicyVersionId"
        ],
        lambda v: v == version_id,
        timeout_s=450.0,
        tolerate_not_found=True,
    )
    return version_id


def _list_version_ids(nm, cn_id):
    versions = nm.list_core_network_policy_versions(CoreNetworkId=cn_id)["CoreNetworkPolicyVersions"]
    return {v["PolicyVersionId"] for v in versions}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
