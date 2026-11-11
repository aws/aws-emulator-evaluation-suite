"""list-data-automation-library-ingestion-jobs-empty-for-new-library."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-data-automation-library-ingestion-jobs-empty-for-new-library"
GROUP = "listing"
SERVICES = ["bedrock-data-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created Library with no ingestion jobs ever invoked against it reports an
    empty ListDataAutomationLibraryIngestionJobs result."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bda-lib-emptyjobs")
    tag_list = [{"key": "sim2real-check", "value": CHECK}]
    arn = bda.create_data_automation_library(libraryName=name, tags=tag_list)["libraryArn"]
    ctx.on_cleanup(lambda: bda.delete_data_automation_library(libraryArn=arn))

    resp = bda.list_data_automation_library_ingestion_jobs(libraryArn=arn)
    jobs = resp["jobs"]
    assert jobs == [], f"expected no ingestion jobs for a freshly created library, got {jobs!r}"
    assert resp.get("nextToken") is None, (
        f"expected no pagination token for an empty result, got {resp.get('nextToken')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
