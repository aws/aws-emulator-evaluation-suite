"""list-applications-pagination-and-contents."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-applications-pagination-and-contents"
GROUP = "data-plane"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-list-applications-pagination"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListApplications returns newly created applications and paginates correctly via NextToken."""
    appconfig = ctx.client("appconfig")

    created_ids = []
    created_names_by_id = {}
    for _ in range(3):
        name = ctx.unique_name("sim2real-behav-app-")
        app = appconfig.create_application(Name=name, Tags=_TAGS)
        app_id = app["Id"]
        ctx.on_cleanup(lambda app_id=app_id: appconfig.delete_application(ApplicationId=app_id))
        created_ids.append(app_id)
        created_names_by_id[app_id] = name

    seen_names_by_id = {}
    next_token = None
    pages_fetched = 0
    while True:
        kwargs = {"MaxResults": 1}
        if next_token:
            kwargs["NextToken"] = next_token
        page = appconfig.list_applications(**kwargs)
        pages_fetched += 1
        for item in page["Items"]:
            assert item["Id"] not in seen_names_by_id, f"duplicate {item['Id']!r} across pages"
            seen_names_by_id[item["Id"]] = item["Name"]
        next_token = page.get("NextToken")
        if not next_token:
            break
        assert pages_fetched < 500, "pagination did not terminate"

    # Forcing MaxResults=1 with >=3 created apps must require multiple page fetches.
    assert pages_fetched >= 3, f"expected >=3 pages with MaxResults=1, got {pages_fetched}"

    # Every created application is present, via the paginated sweep, with its exact Name --
    # not just its Id -- so a target that echoes back a stale or mismatched Name still fails.
    for app_id, name in created_names_by_id.items():
        assert app_id in seen_names_by_id, f"{app_id!r} missing from paginated ListApplications"
        assert seen_names_by_id[app_id] == name, (
            f"Name mismatch for {app_id!r}: expected {name!r}, got {seen_names_by_id[app_id]!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
