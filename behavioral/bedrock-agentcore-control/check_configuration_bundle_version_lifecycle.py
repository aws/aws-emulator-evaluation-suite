"""configuration-bundle-version-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-bundle-version-lifecycle"
GROUP = "state"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateConfigurationBundle with parentVersionIds=[v1] mints a distinct v2 while v1 still reads setting "v1" and
    v2 reads "v2", ListConfigurationBundleVersions lists both, and after delete Get and Update answer
    ResourceNotFoundException "Configuration bundle not found"."""
    control = ctx.client("bedrock-agentcore-control")

    bundle_name = _no_hyphen_name(ctx, "sim2realbundle")
    component_id = "sim2realTestComponent"

    create_resp = control.create_configuration_bundle(
        bundleName=bundle_name,
        components={component_id: {"configuration": {"setting": "v1"}}},
        commitMessage="sim2real initial version",
        tags={"sim2real-check": CHECK},
    )
    bundle_id = create_resp["bundleId"]
    version_1 = create_resp["versionId"]
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: control.delete_configuration_bundle(bundleId=bundle_id))
    )

    v1_fetched = control.get_configuration_bundle_version(
        bundleId=bundle_id, versionId=version_1
    )
    v1_setting = v1_fetched["components"][component_id]["configuration"]["setting"]
    assert v1_setting == "v1", f"expected version 1 setting 'v1', got {v1_setting!r}"

    update_resp = control.update_configuration_bundle(
        bundleId=bundle_id,
        components={component_id: {"configuration": {"setting": "v2"}}},
        commitMessage="sim2real second version",
        parentVersionIds=[version_1],
    )
    version_2 = update_resp["versionId"]
    assert version_2 != version_1, (
        f"expected update to mint a distinct version id, got the same id {version_2!r} back"
    )

    # version 1's own component configuration is immutable/frozen.
    v1_again = control.get_configuration_bundle_version(
        bundleId=bundle_id, versionId=version_1
    )
    v1_again_setting = v1_again["components"][component_id]["configuration"]["setting"]
    assert v1_again_setting == "v1", (
        f"expected version 1 to stay frozen at 'v1' after updating to version 2, "
        f"got {v1_again_setting!r}"
    )

    v2_fetched = control.get_configuration_bundle_version(
        bundleId=bundle_id, versionId=version_2
    )
    v2_setting = v2_fetched["components"][component_id]["configuration"]["setting"]
    assert v2_setting == "v2", f"expected version 2 setting 'v2', got {v2_setting!r}"

    versions = control.list_configuration_bundle_versions(bundleId=bundle_id)
    version_ids = {v["versionId"] for v in versions["versions"]}
    assert {version_1, version_2} <= version_ids, (
        f"expected both {version_1!r} and {version_2!r} enumerated, got {version_ids!r}"
    )

    control.delete_configuration_bundle(bundleId=bundle_id)
    code, message = _error(lambda: control.get_configuration_bundle(bundleId=bundle_id))
    assert code == "ResourceNotFoundException", (
        f"expected GetConfigurationBundle on a deleted bundle to fail with "
        f"ResourceNotFoundException, got {code!r}"
    )
    expected = "Configuration bundle not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the deleted bundle is also unusable for mutation, not just unreadable.
    update_code, update_message = _error(
        lambda: control.update_configuration_bundle(
            bundleId=bundle_id,
            components={component_id: {"configuration": {"setting": "v3"}}},
            commitMessage="sim2real post-delete update",
            parentVersionIds=[version_2],
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateConfigurationBundle on a deleted bundle to fail with "
        f"ResourceNotFoundException, got {update_code!r}"
    )
    expected = "Configuration bundle not found"
    assert update_message == expected, f"expected message {expected!r}, got {update_message!r}"


def _no_hyphen_name(ctx, prefix):
    raw = ctx.unique_name(f"{prefix}-")
    sanitized = "".join(ch for ch in raw if ch.isalnum() or ch == "_")
    return sanitized[:40]


def _error(fn):
    """Return (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

