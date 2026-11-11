"""list-tenants-paginator-walks-every-tenant-once."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-tenants-paginator-walks-every-tenant-once"
GROUP = "tenants"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTenants walked with PageSize=2 returns at most 2 tenants per page, no tenant twice, and every tenant
    the check created exactly once across the NextToken-chained pages.
    """
    sesv2 = ctx.client("sesv2")

    names = [ctx.unique_name("sim2real-tenant-pg-") for _ in range(3)]
    for name in names:
        sesv2.create_tenant(TenantName=name, Tags=[{"Key": "sim2real", "Value": CHECK}])
        ctx.on_cleanup(lambda _n=name: sesv2.delete_tenant(TenantName=_n))

    # ListTenants can lag CreateTenant by a short, bounded window; poll the full walk
    # (never a bare sleep) until every created tenant has propagated.
    listed: list[str] = []
    deadline = time.monotonic() + 30
    while True:
        listed = _walk_all_pages(sesv2)
        ours_listed = [n for n in listed if n in names]
        if sorted(ours_listed) == sorted(names) or time.monotonic() >= deadline:
            break
        time.sleep(1)

    assert len(listed) == len(set(listed)), f"ListTenants paging produced a duplicate: {listed!r}"
    assert sorted(ours_listed) == sorted(names), (
        f"expected every created tenant to appear exactly once across the walk; "
        f"created={names!r}, found={ours_listed!r}"
    )


def _walk_all_pages(sesv2) -> list[str]:
    listed: list[str] = []
    for page in sesv2.get_paginator("list_tenants").paginate(PageSize=2):
        page_names = [t["TenantName"] for t in page.get("Tenants", [])]
        assert len(page_names) <= 2, f"expected at most 2 items per page, got {page_names!r}"
        listed.extend(page_names)
    return listed


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
