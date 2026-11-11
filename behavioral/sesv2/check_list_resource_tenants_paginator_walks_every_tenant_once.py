"""list-resource-tenants-paginator-walks-every-tenant-once."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-resource-tenants-paginator-walks-every-tenant-once"
GROUP = "tenants"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResourceTenants' paginator with PageSize=2 returns every tenant associated with the
    configuration set exactly once, and no page exceeds the requested size.
    """
    sesv2 = ctx.client("sesv2")

    cfg_set_name = ctx.unique_name("sim2real-cfgset-")
    sesv2.create_configuration_set(ConfigurationSetName=cfg_set_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=cfg_set_name))
    cfg_set_arn = f"arn:aws:ses:{ctx.region}:{ctx.account}:configuration-set/{cfg_set_name}"

    tenant_names = [ctx.unique_name("sim2real-tenant-pg-") for _ in range(3)]
    for name in tenant_names:
        sesv2.create_tenant(TenantName=name, Tags=[{"Key": "sim2real", "Value": CHECK}])
        ctx.on_cleanup(lambda _n=name: sesv2.delete_tenant(TenantName=_n))
        sesv2.create_tenant_resource_association(TenantName=name, ResourceArn=cfg_set_arn)
        ctx.on_cleanup(
            lambda _n=name: sesv2.delete_tenant_resource_association(
                TenantName=_n, ResourceArn=cfg_set_arn
            )
        )

    # ListResourceTenants can briefly lag CreateTenantResourceAssociation, so the walk is polled.
    listed: list[str] = []
    deadline = time.monotonic() + 30
    while True:
        listed = _walk_all_pages(sesv2, cfg_set_arn)
        if sorted(listed) == sorted(tenant_names) or time.monotonic() >= deadline:
            break
        time.sleep(1)

    assert len(listed) == len(set(listed)), (
        f"ListResourceTenants paging produced a duplicate: {listed!r}"
    )
    assert sorted(listed) == sorted(tenant_names), (
        f"expected every associated tenant to appear exactly once across the walk; "
        f"associated={tenant_names!r}, found={listed!r}"
    )


def _walk_all_pages(sesv2, cfg_set_arn: str) -> list[str]:
    listed: list[str] = []
    for page in sesv2.get_paginator("list_resource_tenants").paginate(
        ResourceArn=cfg_set_arn, PageSize=2
    ):
        page_names = [t["TenantName"] for t in page.get("ResourceTenants", [])]
        assert len(page_names) <= 2, f"expected at most 2 items per page, got {page_names!r}"
        listed.extend(page_names)
    return listed


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
