"""data-catalog-delete-reserved-aws-data-catalog-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "data-catalog-delete-reserved-aws-data-catalog-fails"
GROUP = 'overly-permissive'
SERVICES = ['athena']

def _list_all(athena, method_name, result_key, **kwargs):
    method = getattr(athena, method_name)
    items = []
    token = None
    while True:
        call = dict(kwargs)
        if token:
            call["NextToken"] = token
        resp = method(**call)
        items.extend(resp.get(result_key, []))
        token = resp.get("NextToken")
        if not token:
            return items

def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts what real AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The built-in AwsDataCatalog is protected from deletion, distinctly from an
    ordinary catalog which DeleteDataCatalog genuinely removes."""
    athena = ctx.client("athena")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: DeleteDataCatalog on a real, customer-owned catalog
    # actually succeeds -- without this, a target that rejects every delete
    # would pass the assertions below for the wrong reason.
    name = ctx.unique_name("sim2real-athena-delcat-")
    created = True
    athena.create_data_catalog(
        Name=name,
        Type="GLUE",
        Parameters={"catalog-id": account_id},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    def _cleanup():
        if created:
            from botocore.exceptions import ClientError

            try:
                athena.delete_data_catalog(Name=name)
            except ClientError as exc:
                # Only an unknown catalog ("DataCatalog ... was not found") means nothing is left.
                if "not found" not in exc.response["Error"].get("Message", ""):
                    raise

    ctx.on_cleanup(_cleanup)

    control_names = {c["CatalogName"] for c in _list_all(athena, "list_data_catalogs", "DataCatalogsSummary")}
    assert name in control_names, f"created catalog {name} missing from ListDataCatalogs"

    athena.delete_data_catalog(Name=name)
    created = False
    control_names_after = {
        c["CatalogName"] for c in _list_all(athena, "list_data_catalogs", "DataCatalogsSummary")
    }
    assert name not in control_names_after, f"deleted catalog {name} still listed after delete"

    # AwsDataCatalog is the implicit built-in catalog: it is enumerated by
    # ListDataCatalogs but is not a deletable customer-owned resource.
    names = {c["CatalogName"] for c in _list_all(athena, "list_data_catalogs", "DataCatalogsSummary")}
    assert "AwsDataCatalog" in names, (
        f"built-in AwsDataCatalog missing from ListDataCatalogs: {sorted(names)}"
    )

    code, message = _error(lambda: athena.delete_data_catalog(Name="AwsDataCatalog"))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}: {message}"
    assert message == "Cannot delete AwsDataCatalog.", message

    # still enumerated after the rejected delete
    names_after = {
        c["CatalogName"] for c in _list_all(athena, "list_data_catalogs", "DataCatalogsSummary")
    }
    assert "AwsDataCatalog" in names_after, "reserved catalog disappeared after rejected delete"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
