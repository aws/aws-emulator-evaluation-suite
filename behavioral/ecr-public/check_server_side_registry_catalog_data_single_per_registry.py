"""server-side-registry-catalog-data-single-per-registry."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "server-side-registry-catalog-data-single-per-registry"
GROUP = "server-side"
SERVICES = ["ecr-public"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-public-registry-catalog")
def run(ctx) -> None:
    """PutRegistryCatalogData maintains a single server-managed catalog record per registry:
    each call fully REPLACES prior fields rather than merging with them."""
    ecrpublic = _ecrpublic(ctx)
    baseline = ecrpublic.get_registry_catalog_data()["registryCatalogData"].get("displayName", "")
    ctx.on_cleanup(lambda: _restore(ecrpublic, baseline))

    # The API docs' "Important" note on RegistryCatalogData says only verified-badge
    # accounts "can have" a displayName, but PutRegistryCatalogData stores and returns
    # a non-empty value regardless (verified: false storing displayName here included) --
    # the badge only gates rendering on the public Gallery.
    first = ctx.unique_name("sim2real-regcat-a-")[:100]
    ecrpublic.put_registry_catalog_data(displayName=first)

    got = ecrpublic.get_registry_catalog_data()["registryCatalogData"]
    assert got.get("displayName") == first, (
        f"GetRegistryCatalogData must read back the just-written displayName; "
        f"got {got.get('displayName')!r}, expected {first!r}"
    )

    second = ctx.unique_name("sim2real-regcat-b-")[:100]
    ecrpublic.put_registry_catalog_data(displayName=second)
    got = ecrpublic.get_registry_catalog_data()["registryCatalogData"]
    # Full replace, not merge/append: the record shows ONLY the second value, never both.
    assert got.get("displayName") == second, (
        f"a second PutRegistryCatalogData must fully replace the prior displayName; "
        f"got {got.get('displayName')!r}, expected {second!r}"
    )
    assert first not in got.get("displayName", ""), (
        f"the first displayName {first!r} leaked into the record after being replaced "
        f"by {second!r}: got {got.get('displayName')!r}"
    )

    # Explicitly clearing (empty string, the field's documented minimum length) wipes the
    # prior value entirely rather than leaving it in place -- further confirming the record
    # is replaced wholesale on every call, never merged field-by-field.
    ecrpublic.put_registry_catalog_data(displayName="")
    got = ecrpublic.get_registry_catalog_data()["registryCatalogData"]
    assert got.get("displayName", "") == "", (
        f"an explicit empty-string PutRegistryCatalogData must wipe the prior displayName "
        f"entirely; got {got.get('displayName')!r}, expected ''"
    )


# ===== helpers =====
def _restore(ecrpublic, original_display_name):
    """Put back the registry's original displayName; the registry record always exists."""
    ecrpublic.put_registry_catalog_data(displayName=original_display_name)


def _ecrpublic(ctx):
    """ecr-public's control-plane API is served only from us-east-1, so pin that region on the
    target ctx names."""
    from botocore.config import Config

    return ctx.client("ecr-public", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"}))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
