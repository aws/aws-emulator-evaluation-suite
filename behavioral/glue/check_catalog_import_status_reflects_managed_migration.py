"""catalog-import-status-reflects-managed-migration."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "catalog-import-status-reflects-managed-migration"
GROUP = "server-side"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCatalogImportStatus reports ImportCompleted True with ImportedBy 'StatusSetByDefault'."""
    glue = ctx.client("glue")
    status = glue.get_catalog_import_status()["ImportStatus"]
    assert status["ImportCompleted"] is True, (
        f"expected the account-wide migration to already be complete, "
        f"got ImportCompleted={status['ImportCompleted']!r}"
    )
    assert status["ImportedBy"] == "StatusSetByDefault", (
        f"expected ImportedBy to reflect the server-managed default rather than a "
        f"caller-driven ImportCatalogToGlue call, got ImportedBy={status['ImportedBy']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
