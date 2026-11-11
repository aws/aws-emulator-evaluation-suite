"""catalog-invalid-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "catalog-invalid-name-rejected"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCatalog rejects a name containing '.' with a name-specific InvalidInputException message,
    distinct from the native-catalog refusal a valid name gets, and GetCatalog then finds neither catalog.
    """
    glue = ctx.client("glue")

    invalid_name = ctx.unique_name("sim2real-behav-catbad-").lower().replace("_", "-") + ".invalid"
    valid_name = ctx.unique_name("sim2real-behav-catgood-").lower().replace("_", "-")

    code_invalid, msg_invalid = _error(lambda: glue.create_catalog(Name=invalid_name, CatalogInput={}))
    assert code_invalid == "InvalidInputException", code_invalid
    assert msg_invalid == "Only lowercase letters, numbers, underscores and hyphens are allowed for catalog name", msg_invalid

    code_valid, msg_valid = _error(lambda: glue.create_catalog(Name=valid_name, CatalogInput={}))
    assert code_valid == "InvalidInputException", code_valid
    assert msg_valid == "Create glue native catalog is not supported.", msg_valid

    # Effect absent: neither name resulted in a catalog actually being created.
    get_code_invalid, get_msg_invalid = _error(lambda: glue.get_catalog(CatalogId=invalid_name))
    assert get_code_invalid == "ValidationException", (
        f"expected a not-found-shaped error for the never-created invalid-name catalog, got {get_code_invalid!r}"
    )
    assert get_msg_invalid == (
        f"1 validation error detected: Value '{invalid_name}' at 'name' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: ^(?!(.*[.\\/\\\\]|aws:)).*$"
    ), get_msg_invalid

    get_code_valid, get_msg_valid = _error(lambda: glue.get_catalog(CatalogId=valid_name))
    assert get_code_valid == "EntityNotFoundException", get_code_valid
    assert get_msg_valid == "Catalog not found.", get_msg_valid


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises: real AWS refuses it."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

