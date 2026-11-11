"""root-catalog-delete-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "root-catalog-delete-rejected"
GROUP = "state-machine"
SERVICES = ["glue"]


def _error(fn):
    """Call fn() and return (code, message) of the refusal; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCatalog returns the account's root catalog; DeleteCatalog on it raises
    InvalidInputException with the exact message and leaves it gettable; GetCatalog on an unknown
    nested id raises EntityNotFoundException ("Catalog not found.").
    """
    glue = ctx.client("glue")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    got = glue.get_catalog(CatalogId=account_id)["Catalog"]
    assert got["CatalogId"] == account_id or got.get("Name") == account_id, got

    # The root catalog cannot be deleted; assert it stays intact afterward (effect absent).
    code, message = _error(lambda: glue.delete_catalog(CatalogId=account_id))
    assert code == "InvalidInputException", f"unexpected code: {code}"
    assert message == "Only lowercase letters, numbers, underscores and hyphens are allowed for catalog name", message

    still_there = glue.get_catalog(CatalogId=account_id)["Catalog"]
    assert still_there["CatalogId"] == account_id or still_there.get("Name") == account_id, still_there

    # Overly-permissive guard: GetCatalog for a nonexistent nested catalog under the root 404s.
    bogus_nested = f"{account_id}/sim2real-behav-no-such-nested-catalog"
    bogus_code, bogus_message = _error(lambda: glue.get_catalog(CatalogId=bogus_nested))
    assert bogus_code == "EntityNotFoundException", f"unexpected code: {bogus_code}"
    assert bogus_message == "Catalog not found.", bogus_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

