"""create-data-automation-library-active-immediately."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-data-automation-library-active-immediately"
GROUP = "lifecycle-library"
SERVICES = ["bedrock-data-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataAutomationLibrary transitions straight to ACTIVE (no intermediate provisioning state)."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-lib-")
    description = "behavioral fidelity test"
    created = bda.create_data_automation_library(libraryName=name, libraryDescription=description)
    library_arn = created["libraryArn"]
    ctx.on_cleanup(lambda: bda.delete_data_automation_library(libraryArn=library_arn))
    assert created["status"] == "ACTIVE", f"expected ACTIVE on create, got {created['status']!r}"

    fetched = bda.get_data_automation_library(libraryArn=library_arn)["library"]
    assert fetched["status"] == "ACTIVE", f"expected ACTIVE on independent get, got {fetched['status']!r}"
    assert fetched["libraryName"] == name, f"expected libraryName {name!r}, got {fetched['libraryName']!r}"
    assert fetched["libraryDescription"] == description, (
        f"expected libraryDescription {description!r} to persist from create, got "
        f"{fetched['libraryDescription']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
