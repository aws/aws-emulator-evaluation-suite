"""list-packaging-configurations-pagination-no-duplicates."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-packaging-configurations-pagination-no-duplicates"
GROUP = "state"
SERVICES = ["mediapackage-vod"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListPackagingConfigurations with a small MaxResults returns every created
    configuration exactly once, each page respecting the requested page size."""
    mpv = ctx.client("mediapackage-vod")
    group_id = ctx.unique_name("sim2real-mpvod-group-")
    mpv.create_packaging_group(Id=group_id, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: mpv.delete_packaging_group(Id=group_id))

    created_ids = []
    for i in range(5):
        config_id = ctx.unique_name(f"sim2real-mpvod-pgcfg{i}-")
        mpv.create_packaging_configuration(
            Id=config_id,
            PackagingGroupId=group_id,
            HlsPackage={"HlsManifests": [{"ManifestName": "index"}]},
            Tags={"sim2real": "true"},
        )
        ctx.on_cleanup(lambda cid=config_id: mpv.delete_packaging_configuration(Id=cid))
        created_ids.append(config_id)
    created_ids_set = set(created_ids)

    seen: list[str] = []
    next_token = None
    pages = 0
    while True:
        kwargs = {"PackagingGroupId": group_id, "MaxResults": 2}
        if next_token:
            kwargs["NextToken"] = next_token
        page = mpv.list_packaging_configurations(**kwargs)
        page_ids = [c["Id"] for c in page["PackagingConfigurations"]]
        assert len(page_ids) <= 2, f"page returned {len(page_ids)} items, exceeds MaxResults=2"
        seen.extend(page_ids)
        pages += 1
        next_token = page.get("NextToken")
        if not next_token or pages > 20:
            break

    seen_in_scope = [i for i in seen if i in created_ids_set]
    assert len(seen_in_scope) == len(set(seen_in_scope)), "duplicate configuration Id across pages"
    assert set(seen_in_scope) == created_ids_set, "not every created configuration was listed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
