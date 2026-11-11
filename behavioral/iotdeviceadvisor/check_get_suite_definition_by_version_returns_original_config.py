"""get-suite-definition-by-version-returns-original-config."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-suite-definition-by-version-returns-original-config"
GROUP = "lifecycle"
SERVICES = ["iotdeviceadvisor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After UpdateSuiteDefinition mints a new version, GetSuiteDefinition for the old version echoes that
    version string but serves the current configuration, with latestVersion the new one."""
    da = ctx.client("iotdeviceadvisor")
    role_arn = _dummy_role_arn(ctx)
    original_name = ctx.unique_name("sim2real-behav-suite-")

    create_resp = da.create_suite_definition(
        suiteDefinitionConfiguration={
            "suiteDefinitionName": original_name,
            "rootGroup": "",
            "devicePermissionRoleArn": role_arn,
            "intendedForQualification": True,
        },
        tags={"env": "sim2real", "purpose": "behavioral-check"},
    )
    suite_id = create_resp["suiteDefinitionId"]
    ctx.on_cleanup(lambda: da.delete_suite_definition(suiteDefinitionId=suite_id))

    v1 = da.get_suite_definition(suiteDefinitionId=suite_id)["suiteDefinitionVersion"]

    new_name = original_name + "-v2"
    update_resp = da.update_suite_definition(
        suiteDefinitionId=suite_id,
        suiteDefinitionConfiguration={
            "suiteDefinitionName": new_name,
            "rootGroup": "",
            "devicePermissionRoleArn": role_arn,
            "intendedForQualification": True,
        },
    )
    v2 = update_resp["suiteDefinitionVersion"]
    assert v2 != v1, f"expected UpdateSuiteDefinition to mint a new version, got v1={v1!r} v2={v2!r}"

    # requesting the OLD version number by id still succeeds and echoes that version
    # string back, but serves the CURRENT config (no per-version config snapshot exists)
    historical = da.get_suite_definition(suiteDefinitionId=suite_id, suiteDefinitionVersion=v1)
    assert historical["suiteDefinitionVersion"] == v1, (
        f"expected GetSuiteDefinition(version={v1!r}) to echo the requested version, "
        f"got {historical['suiteDefinitionVersion']!r}"
    )
    assert historical["suiteDefinitionConfiguration"]["suiteDefinitionName"] == new_name, (
        f"expected the v1 read to serve the CURRENT config name {new_name!r} "
        f"(no per-version snapshot), got {historical['suiteDefinitionConfiguration']['suiteDefinitionName']!r}"
    )
    # latestVersion always reflects the newest version, even when reading an old one
    assert historical["latestVersion"] == v2, (
        f"expected latestVersion to be {v2!r} even when reading v1, got {historical['latestVersion']!r}"
    )

    current = da.get_suite_definition(suiteDefinitionId=suite_id, suiteDefinitionVersion=v2)
    assert current["suiteDefinitionConfiguration"]["suiteDefinitionName"] == new_name, (
        f"expected GetSuiteDefinition(version={v2!r}) to serve {new_name!r}, "
        f"got {current['suiteDefinitionConfiguration']['suiteDefinitionName']!r}"
    )


def _dummy_role_arn(ctx) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:iam::{account_id}:role/sim2real-behav-nonexistent-role"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
