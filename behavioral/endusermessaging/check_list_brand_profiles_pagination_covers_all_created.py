"""list-brand-profiles-pagination-covers-all-created."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-brand-profiles-pagination-covers-all-created"
GROUP = 'brand-profiles'
SERVICES = ['endusermessaging']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListBrandProfiles paginated with a page size smaller than the created count still
    surfaces every one of them exactly once across pages, via nextToken.
    """
    eum = ctx.client("endusermessaging")
    base = ctx.unique_name("sim2real-behav-eum-bplist-")
    wanted_names = {f"{base}{i}" for i in range(3)}

    created_ids = {}
    for wanted_name in wanted_names:
        bpid = eum.create_brand_profile(brandProfileName=wanted_name)["brandProfileId"]
        created_ids[bpid] = wanted_name
        ctx.on_cleanup(_teardown(lambda bpid=bpid: eum.delete_brand_profile(brandProfileId=bpid),
                                  "ResourceNotFoundException"))

    pages = eum.get_paginator("list_brand_profiles").paginate(PaginationConfig={"PageSize": 1})
    seen_names = {}
    for page in pages:
        for bp in page["brandProfiles"]:
            if bp["brandProfileId"] in created_ids:
                seen_names[bp["brandProfileId"]] = bp["brandProfileName"]

    assert set(seen_names) == set(created_ids), (
        f"pagination missed some of our profiles: created {sorted(created_ids)}, saw {sorted(seen_names)}"
    )
    assert seen_names == created_ids, f"a listed name disagreed with what was created: {seen_names!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
