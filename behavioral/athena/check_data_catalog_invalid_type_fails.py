"""data-catalog-invalid-type-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-catalog-invalid-type-fails"
GROUP = 'overly-permissive'
SERVICES = ['athena']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDataCatalog with a Type outside {LAMBDA, GLUE, HIVE} fails and creates no catalog under
    that name, while the same request with a valid Type succeeds."""
    athena = ctx.client("athena")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    control_name = ctx.unique_name("sim2real-behav-cat-ctrl-")
    athena.create_data_catalog(Name=control_name, Type="GLUE", Parameters={"catalog-id": account_id})
    ctx.on_cleanup(lambda: athena.delete_data_catalog(Name=control_name))
    control = athena.get_data_catalog(Name=control_name)["DataCatalog"]
    assert control["Type"] == "GLUE", f"positive control: expected Type GLUE, got {control['Type']!r}"

    name = ctx.unique_name("sim2real-behav-cat-badtype-")
    code, message = _error(lambda: athena.create_data_catalog(Name=name, Type="BOGUS_TYPE"))
    assert code == "InvalidRequestException", f"expected InvalidRequestException for invalid Type, got {code!r}"
    assert message == (
        "1 validation error detected: Value at 'type' failed to satisfy constraint: "
        "Member must satisfy enum value set: [FEDERATED, LAMBDA, HIVE, GLUE]"
    ), message

    # Effect-absent: the rejected create must not have left a catalog behind.
    get_code, get_message = _error(lambda: athena.get_data_catalog(Name=name))
    assert get_code == "InvalidRequestException", (
        f"catalog {name!r} should not exist after a rejected CreateDataCatalog, "
        f"got {get_code!r} from GetDataCatalog"
    )
    assert get_message == f"DataCatalog {name} was not found.", get_message
    list_names = {c["CatalogName"] for c in athena.list_data_catalogs()["DataCatalogsSummary"]}
    assert name not in list_names, f"catalog {name!r} should not appear in ListDataCatalogs after rejection"


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts what real AWS refuses never reads as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
