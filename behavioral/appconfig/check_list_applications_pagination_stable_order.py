"""list-applications-pagination-stable-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-applications-pagination-stable-order"
GROUP = "ordering"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-list-applications-pagination-stable-order"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListApplications one item at a time via NextToken returns every
    created application exactly once (no omission, no duplication), and a second,
    independent full pagination pass returns the identical relative order.
    """
    appconfig = ctx.client("appconfig")
    prefix = ctx.unique_name("sim2real-behav-lap-")
    created_ids = []
    for i in range(5):
        app_id = appconfig.create_application(Name=f"{prefix}{i}", Tags=_TAGS)["Id"]
        created_ids.append(app_id)
        ctx.on_cleanup(lambda aid=app_id: appconfig.delete_application(ApplicationId=aid))

    first_pass = _paginate_all_ids(appconfig)
    second_pass = _paginate_all_ids(appconfig)

    ours_first = [i for i in first_pass if i in created_ids]
    ours_second = [i for i in second_pass if i in created_ids]

    assert sorted(ours_first) == sorted(created_ids), "pagination must not omit any created item"
    assert len(ours_first) == len(set(ours_first)), "pagination must not duplicate an item across pages"
    assert ours_first == ours_second, "two independent full pagination passes must return the same order"


def _paginate_all_ids(appconfig, page_size=1):
    ids = []
    token = None
    while True:
        kwargs = {"MaxResults": page_size}
        if token:
            kwargs["NextToken"] = token
        resp = appconfig.list_applications(**kwargs)
        ids.extend(item["Id"] for item in resp.get("Items", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
