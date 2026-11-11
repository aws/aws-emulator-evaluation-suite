"""glue-database-tags-visible-via-resource-groups-tagging-api."""

from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "glue-database-tags-visible-via-resource-groups-tagging-api"

GROUP = "cross-service-tagging"

SERVICES = ["glue", "resourcegroupstaggingapi"]


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _all_resources(rgt, **kwargs):
    out, token = [], ""
    while True:
        page = rgt.get_resources(**kwargs, **({"PaginationToken": token} if token else {}))
        out.extend(page["ResourceTagMappingList"])
        token = page["PaginationToken"]
        if not token:
            return out


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "concern:e2e",
    "plane:control",
)
def run(ctx) -> None:
    """Tags passed to Glue's CreateDatabase are indexed by the Resource Groups Tagging API without
    a TagResource call: GetResources by the database ARN finds exactly it, with both tags.
    """
    glue = ctx.client("glue")
    rgt = ctx.client("resourcegroupstaggingapi")
    sts = ctx.client("sts")

    account = sts.get_caller_identity()["Account"]
    db_name = ctx.unique_name("sim2real_xsvc_db_")
    glue.create_database(
        DatabaseInput={"Name": db_name, "Description": "cross-service tag visibility"},
        Tags={"Environment": "dev", "Project": "project1"},
    )
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    arn = f"arn:aws:glue:{ctx.region}:{account}:database/{db_name}"

    mappings = _poll_until(
        lambda: _all_resources(rgt, ResourceARNList=[arn]),
        lambda ms: len(ms) == 1,
        description=f"GetResources indexes the Glue database ARN {arn!r}",
    )
    assert len(mappings) == 1, f"expected exactly one mapping for {arn!r}, got {mappings!r}"
    mapping = mappings[0]
    assert mapping["ResourceARN"] == arn, mapping["ResourceARN"]
    found_tags = {t["Key"]: t["Value"] for t in mapping["Tags"]}
    assert found_tags.get("Environment") == "dev", found_tags
    assert found_tags.get("Project") == "project1", found_tags


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
