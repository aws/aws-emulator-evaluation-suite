"""registry-catalog-data-round-trip-unicode."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "registry-catalog-data-round-trip-unicode"
GROUP = "server-side"
SERVICES = ["ecr-public"]


def _ecrpub_client(ctx):
    """ecr-public's control-plane API is served only from us-east-1, so the client pins that
    region; ctx.client keeps an emulator run on the emulator's endpoint."""
    return ctx.client("ecr-public", region="us-east-1")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-public-registry-catalog")
def run(ctx) -> None:
    """Unicode and multi-line displayName text written via PutRegistryCatalogData is returned
    byte-for-byte identical by PutRegistryCatalogData and GetRegistryCatalogData."""
    ecr = _ecrpub_client(ctx)

    # The verified Marketplace badge only gates Gallery rendering of displayName, not the API's
    # store-and-echo, so the round trip runs on an unverified registry too.
    original_catalog = ecr.get_registry_catalog_data()["registryCatalogData"]
    original_display_name = original_catalog.get("displayName", "")

    def _restore() -> None:
        ecr.put_registry_catalog_data(displayName=original_display_name)

    ctx.on_cleanup(_restore)

    display_name = "\u00e9\u00e8\u00ea \u4e2d\u6587\u6d4b\u8bd5 \U0001F680\nline two\nline three \u00df\u00f1\u00fc"
    assert len(display_name) <= 100  # RegistryDisplayName max length constraint

    put_resp = ecr.put_registry_catalog_data(displayName=display_name)
    assert put_resp["registryCatalogData"]["displayName"] == display_name, (
        f"PutRegistryCatalogData must echo the unicode/multi-line displayName verbatim; "
        f"got {put_resp['registryCatalogData'].get('displayName')!r}"
    )

    fetched = ecr.get_registry_catalog_data()["registryCatalogData"]["displayName"]
    assert fetched == display_name, (
        f"GetRegistryCatalogData round-trip mismatch: {fetched!r} != {display_name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
