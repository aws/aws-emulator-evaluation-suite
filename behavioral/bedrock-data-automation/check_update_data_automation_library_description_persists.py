"""update-data-automation-library-description-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-data-automation-library-description-persists"
GROUP = "lifecycle-library"
SERVICES = ["bedrock-data-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDataAutomationLibrary replaces the description in place and keeps status ACTIVE."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-lib-")
    library_arn = bda.create_data_automation_library(
        libraryName=name,
        libraryDescription="original description",
        tags=[{"key": "created-with", "value": "sim2real"}],
    )["libraryArn"]
    ctx.on_cleanup(lambda: bda.delete_data_automation_library(libraryArn=library_arn))

    updated = bda.update_data_automation_library(libraryArn=library_arn, libraryDescription="updated description")
    assert updated["status"] == "ACTIVE", f"expected ACTIVE right after update, got {updated['status']!r}"

    fetched = bda.get_data_automation_library(libraryArn=library_arn)["library"]
    assert fetched["libraryDescription"] == "updated description", (
        f"expected the updated description to persist, got {fetched['libraryDescription']!r}"
    )
    assert fetched["status"] == "ACTIVE", f"expected ACTIVE on independent read, got {fetched['status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
