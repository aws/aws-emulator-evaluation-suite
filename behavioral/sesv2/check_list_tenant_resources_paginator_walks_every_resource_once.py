"""list-tenant-resources-paginator-walks-every-resource-once."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-tenant-resources-paginator-walks-every-resource-once"
GROUP = "tenants"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTenantResources' paginator with PageSize=2 returns every resource associated with the
    tenant exactly once, and no page exceeds the requested size.
    """
    sesv2 = ctx.client("sesv2")

    tenant_name = ctx.unique_name("sim2real-tenant-")
    sesv2.create_tenant(TenantName=tenant_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: sesv2.delete_tenant(TenantName=tenant_name))

    cfg_set_names = [ctx.unique_name("sim2real-cfgset-pg-") for _ in range(3)]
    arns = []
    for name in cfg_set_names:
        sesv2.create_configuration_set(ConfigurationSetName=name, Tags=[{"Key": "sim2real", "Value": CHECK}])
        ctx.on_cleanup(lambda _n=name: sesv2.delete_configuration_set(ConfigurationSetName=_n))
        arn = f"arn:aws:ses:{ctx.region}:{ctx.account}:configuration-set/{name}"
        sesv2.create_tenant_resource_association(TenantName=tenant_name, ResourceArn=arn)
        ctx.on_cleanup(
            lambda _a=arn: sesv2.delete_tenant_resource_association(
                TenantName=tenant_name, ResourceArn=_a
            )
        )
        arns.append(arn)

    # ListTenantResources can briefly lag CreateTenantResourceAssociation, so the walk is polled.
    listed: list[str] = []
    deadline = time.monotonic() + 30
    while True:
        listed = _walk_all_pages(sesv2, tenant_name)
        if sorted(listed) == sorted(arns) or time.monotonic() >= deadline:
            break
        time.sleep(1)

    assert len(listed) == len(set(listed)), (
        f"ListTenantResources paging produced a duplicate: {listed!r}"
    )
    assert sorted(listed) == sorted(arns), (
        f"expected every associated resource to appear exactly once across the walk; "
        f"associated={arns!r}, found={listed!r}"
    )


def _walk_all_pages(sesv2, tenant_name: str) -> list[str]:
    listed: list[str] = []
    for page in sesv2.get_paginator("list_tenant_resources").paginate(
        TenantName=tenant_name, PageSize=2
    ):
        page_arns = [r["ResourceArn"] for r in page.get("TenantResources", [])]
        assert len(page_arns) <= 2, f"expected at most 2 items per page, got {page_arns!r}"
        listed.extend(page_arns)
    return listed


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
