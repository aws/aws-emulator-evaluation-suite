"""registry-catalog-data-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "registry-catalog-data-round-trip"
GROUP = "representation"
SERVICES = ["ecr-public"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-public-registry-catalog")
def run(ctx) -> None:
    """PutRegistryCatalogData round-trips displayName exactly, incl. explicit-empty vs unset."""
    ecrp = _ecr_public(ctx)

    # Registry catalog data is a single mutable per-account record (not a resource we
    # create/delete), so snapshot the original value and restore it on cleanup.
    original = ecrp.get_registry_catalog_data()["registryCatalogData"].get("displayName")

    def _restore() -> None:
        if original is not None:
            ecrp.put_registry_catalog_data(displayName=original)
        else:
            ecrp.put_registry_catalog_data(displayName="")

    ctx.on_cleanup(_restore)

    unique_suffix = ctx.unique_name("sim2real-behav-")
    display_name = f"sim2real behav 名前 \U0001F98A {unique_suffix}"[:100]

    put_resp = ecrp.put_registry_catalog_data(displayName=display_name)
    assert put_resp["registryCatalogData"]["displayName"] == display_name, (
        f"PutRegistryCatalogData did not echo the new displayName: "
        f"{put_resp['registryCatalogData'].get('displayName')!r} != {display_name!r}"
    )

    get_resp = ecrp.get_registry_catalog_data()
    assert get_resp["registryCatalogData"]["displayName"] == display_name, (
        f"displayName mismatch: {get_resp['registryCatalogData']['displayName']!r} "
        f"!= {display_name!r}"
    )

    # Explicit empty string is a distinct, present value -- it must round-trip as "",
    # not disappear from the response the way a wholly-unset field would.
    empty_put_resp = ecrp.put_registry_catalog_data(displayName="")
    assert "displayName" in empty_put_resp["registryCatalogData"], (
        "displayName key vanished from PutRegistryCatalogData response on explicit-empty "
        "set -- it should still be present, just empty"
    )
    assert empty_put_resp["registryCatalogData"]["displayName"] == ""

    empty_get_resp = ecrp.get_registry_catalog_data()
    assert "displayName" in empty_get_resp["registryCatalogData"], (
        "displayName key vanished from GetRegistryCatalogData response on explicit-empty "
        "set -- it should still be present, just empty"
    )
    assert empty_get_resp["registryCatalogData"]["displayName"] == ""


def _ecr_public(ctx):
    """ECR Public is a us-east-1-ONLY API. Pinned through `ctx.client(..., region=)`."""
    return ctx.client("ecr-public", region="us-east-1")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

