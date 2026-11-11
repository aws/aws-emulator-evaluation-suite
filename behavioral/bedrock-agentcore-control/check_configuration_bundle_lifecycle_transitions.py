"""configuration-bundle-lifecycle-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "configuration-bundle-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ConfigurationBundle create->update(new version)->delete; unresolvable post-delete."""
    client = ctx.client("bedrock-agentcore-control")
    bundle_name = _bundle_name(ctx, "sim2realbundle")

    created = client.create_configuration_bundle(
        bundleName=bundle_name,
        description="initial bundle version",
        components={"sim2realComponentA": {"configuration": {"setting": "v1"}}},
        tags={"env": "sim2real-test", "purpose": CHECK},
    )
    bundle_id = created["bundleId"]
    version1 = created["versionId"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client, bundle_id))

    got = client.get_configuration_bundle(bundleId=bundle_id)
    assert got["bundleName"] == bundle_name, f"expected bundleName={bundle_name!r}, got {got['bundleName']!r}"
    got_setting = got["components"]["sim2realComponentA"]["configuration"]["setting"]
    assert got_setting == "v1", f"expected component setting 'v1' right after create, got {got_setting!r}"

    updated = client.update_configuration_bundle(
        bundleId=bundle_id,
        parentVersionIds=[version1],
        components={"sim2realComponentA": {"configuration": {"setting": "v2"}}},
        commitMessage="rotate setting to v2",
    )
    version2 = updated["versionId"]
    assert version2 != version1, f"expected update to mint a new versionId, got the same one back: {version2!r}"

    got_v1 = client.get_configuration_bundle_version(bundleId=bundle_id, versionId=version1)
    v1_setting = got_v1["components"]["sim2realComponentA"]["configuration"]["setting"]
    assert v1_setting == "v1", f"expected version {version1} to remain 'v1' after a later update, got {v1_setting!r}"

    got_latest = client.get_configuration_bundle(bundleId=bundle_id)
    latest_setting = got_latest["components"]["sim2realComponentA"]["configuration"]["setting"]
    assert latest_setting == "v2", f"expected latest read to reflect the update ('v2'), got {latest_setting!r}"
    assert got_latest["versionId"] == version2, (
        f"expected latest read to report versionId={version2!r}, got {got_latest['versionId']!r}"
    )

    delete_resp = client.delete_configuration_bundle(bundleId=bundle_id)
    assert delete_resp["bundleId"] == bundle_id, (
        f"expected delete response to echo bundleId={bundle_id!r}, got {delete_resp['bundleId']!r}"
    )

    final_code, final_message = _error_detail(
        lambda: client.get_configuration_bundle(bundleId=bundle_id), wait_s=120.0
    )
    assert final_code == "ResourceNotFoundException", (
        f"expected GetConfigurationBundle on a deleted bundle to report ResourceNotFoundException, got {final_code!r}"
    )
    assert final_message == "Configuration bundle not found", (
        f"expected message 'Configuration bundle not found', got {final_message!r}"
    )

    mutate_code, mutate_message = _error_detail(
        lambda: client.update_configuration_bundle(
            bundleId=bundle_id,
            parentVersionIds=[version2],
            components={"sim2realComponentA": {"configuration": {"setting": "v3"}}},
            commitMessage="mutate after delete",
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected UpdateConfigurationBundle on a deleted bundle to also report ResourceNotFoundException, "
        f"got {mutate_code!r}"
    )
    assert mutate_message == "Configuration bundle not found", (
        f"expected message 'Configuration bundle not found', got {mutate_message!r}"
    )


def _bundle_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch == "_")


def _error_detail(fn, *, wait_s=0.0, interval_s=3.0):
    """Return (code, message) of the ClientError fn raises. While fn still succeeds it is
    retried until wait_s elapses; a success at the deadline raises AssertionError."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + wait_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
        time.sleep(interval_s)


def _delete_ignore_not_found(client, bundle_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        client.delete_configuration_bundle(bundleId=bundle_id)
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
