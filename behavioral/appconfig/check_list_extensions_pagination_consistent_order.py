"""list-extensions-pagination-consistent-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-extensions-pagination-consistent-order"
GROUP = "ordering"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListExtensions one item per page returns each of five new extensions exactly
    once, and a second full pass lists every extension common to both passes in the same order.
    """
    appconfig = ctx.client("appconfig")
    action_uri = f"arn:aws:sns:{ctx.region}:{_account_id(ctx)}:sim2real-appconfig-ext-notify"
    prefix = ctx.unique_name("sim2real-behav-lext-")
    created_ids = []
    for i in range(5):
        ext_id = appconfig.create_extension(
            Name=f"{prefix}{i}",
            Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "noop", "Uri": action_uri}]},
            Tags={"sim2real": "list-extensions-pagination-consistent-order"},
        )["Id"]
        created_ids.append(ext_id)
        ctx.on_cleanup(lambda eid=ext_id: appconfig.delete_extension(ExtensionIdentifier=eid))

    first_pass = _paginate_all_ids(appconfig)
    second_pass = _paginate_all_ids(appconfig)

    ours_first = [i for i in first_pass if i in created_ids]
    ours_second = [i for i in second_pass if i in created_ids]

    assert sorted(ours_first) == sorted(created_ids), "pagination must not omit any created item"
    assert len(ours_first) == len(set(ours_first)), "pagination must not duplicate an item across pages"
    assert sorted(ours_second) == sorted(created_ids), (
        f"the second pass must list every created item once, got {ours_second}"
    )
    # Other extensions in the account may appear or disappear between passes; every
    # extension listed by both passes keeps its position relative to the others.
    common = set(first_pass) & set(second_pass)
    common_first = [i for i in first_pass if i in common]
    common_second = [i for i in second_pass if i in common]
    assert common_first == common_second, (
        "the listing order (including pre-existing extensions) must be stable across passes, "
        f"got {common_first} then {common_second}"
    )


def _paginate_all_ids(appconfig, page_size=1):
    ids = []
    token = None
    while True:
        kwargs = {"MaxResults": page_size}
        if token:
            kwargs["NextToken"] = token
        resp = appconfig.list_extensions(**kwargs)
        ids.extend(item["Id"] for item in resp.get("Items", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
