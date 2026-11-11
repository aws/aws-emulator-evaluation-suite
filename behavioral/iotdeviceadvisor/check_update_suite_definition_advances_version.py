"""update-suite-definition-advances-version."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-suite-definition-advances-version"
GROUP = "lifecycle"
SERVICES = ["iotdeviceadvisor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSuiteDefinition creates a new version and latestVersion advances to it."""
    da = ctx.client("iotdeviceadvisor")
    role_arn = _dummy_role_arn(ctx)
    name = ctx.unique_name("sim2real-behav-suite-")

    create_resp = da.create_suite_definition(
        suiteDefinitionConfiguration={
            "suiteDefinitionName": name,
            "rootGroup": "",
            "devicePermissionRoleArn": role_arn,
            "intendedForQualification": True,
        },
        tags={"env": "sim2real", "purpose": "behavioral-check"},
    )
    suite_id = create_resp["suiteDefinitionId"]
    ctx.on_cleanup(lambda: da.delete_suite_definition(suiteDefinitionId=suite_id))

    before = da.get_suite_definition(suiteDefinitionId=suite_id)
    v1 = before["suiteDefinitionVersion"]
    created_at = before["createdAt"]
    modified_at_v1 = before["lastModifiedAt"]

    updated_name = name + "-v2"
    update_resp = da.update_suite_definition(
        suiteDefinitionId=suite_id,
        suiteDefinitionConfiguration={
            "suiteDefinitionName": updated_name,
            "rootGroup": "",
            "devicePermissionRoleArn": role_arn,
            "intendedForQualification": True,
        },
    )
    v2 = update_resp["suiteDefinitionVersion"]
    assert v2 != v1, f"expected update to advance the version past {v1!r}, got {v2!r}"
    assert update_resp["suiteDefinitionName"] == updated_name, (
        f"expected update response name {updated_name!r}, got {update_resp['suiteDefinitionName']!r}"
    )

    latest = da.get_suite_definition(suiteDefinitionId=suite_id)
    assert latest["suiteDefinitionVersion"] == v2, (
        f"expected default GetSuiteDefinition to serve the new version {v2!r}, got {latest['suiteDefinitionVersion']!r}"
    )
    assert latest["latestVersion"] == v2, (
        f"expected latestVersion {v2!r}, got {latest['latestVersion']!r}"
    )
    assert latest["suiteDefinitionConfiguration"]["suiteDefinitionName"] == updated_name, (
        f"expected served config name {updated_name!r}, got "
        f"{latest['suiteDefinitionConfiguration']['suiteDefinitionName']!r}"
    )
    # measured, not assumed: real AWS rewrites createdAt on every UpdateSuiteDefinition too --
    # it is a last-write timestamp for the one live record, not the original creation time.
    assert latest["createdAt"] > created_at, (
        f"expected createdAt to advance past {created_at!r} after update, got {latest['createdAt']!r}"
    )
    assert latest["lastModifiedAt"] > modified_at_v1, (
        f"expected lastModifiedAt to advance past {modified_at_v1!r} after update, got {latest['lastModifiedAt']!r}"
    )


def _dummy_role_arn(ctx) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:iam::{account_id}:role/sim2real-behav-nonexistent-role"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
