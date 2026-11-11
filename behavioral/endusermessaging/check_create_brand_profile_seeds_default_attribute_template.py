"""create-brand-profile-seeds-default-attribute-template."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-brand-profile-seeds-default-attribute-template"
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
    """CreateBrandProfile's attributesCreated count equals the full set of attribute names
    a paginated ListBrandProfileAttributes returns right after.
    """
    eum = ctx.client("endusermessaging")
    name = ctx.unique_name("sim2real-behav-eum-bp-")

    created = eum.create_brand_profile(brandProfileName=name)
    bpid = created["brandProfileId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_brand_profile(brandProfileId=bpid),
                             "ResourceNotFoundException"))
    seeded = created["attributesCreated"]
    assert seeded > 0, f"attributesCreated was {seeded!r}, expected a positive seed count"

    pages = eum.get_paginator("list_brand_profile_attributes").paginate(
        brandProfileId=bpid, PaginationConfig={"PageSize": 5}
    )
    names = [a["attributeName"] for page in pages for a in page["brandProfileAttributes"]]
    assert len(names) == seeded, (
        f"ListBrandProfileAttributes returned {len(names)} names, but attributesCreated said {seeded}"
    )
    assert len(set(names)) == len(names), f"duplicate attribute names in the seeded template: {names!r}"
    assert all(n.strip() for n in names), f"a seeded attribute name was blank: {names!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
