"""put-registry-catalog-data-unicode-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-registry-catalog-data-unicode-preserved"
GROUP = "representation"
SERVICES = ["ecr-public"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-public-registry-catalog")
def run(ctx) -> None:
    """A Unicode registry displayName written by PutRegistryCatalogData reads back byte-identical
    from GetRegistryCatalogData.
    """
    ecrpublic = _ecrpublic(ctx)

    original = ecrpublic.get_registry_catalog_data().get("registryCatalogData", {}).get("displayName", "")
    # Registry catalog data is account-wide, so the prior displayName is restored, not deleted.
    ctx.on_cleanup(lambda: ecrpublic.put_registry_catalog_data(displayName=original))

    unicode_name = "测试注册表™ · Ünïcödé Registry Ω · façade 日本語 · Café"
    assert len(unicode_name) <= 100, "keep under the 100-char displayName limit"
    assert unicode_name != original, (
        f"the test value must differ from what the account already has, or the round-trip "
        f"below proves nothing: {unicode_name!r} == existing {original!r}"
    )

    ecrpublic.put_registry_catalog_data(displayName=unicode_name)
    got = ecrpublic.get_registry_catalog_data()["registryCatalogData"]["displayName"]

    assert got == unicode_name, f"round-tripped displayName mismatch: {got!r} != {unicode_name!r}"


def _ecrpublic(ctx):
    """An ecr-public client pinned to us-east-1, the only region that serves its API."""
    return ctx.client("ecr-public", region="us-east-1")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
