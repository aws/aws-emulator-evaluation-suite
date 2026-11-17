"""list-data-catalogs-max-results-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-data-catalogs-max-results-out-of-range-rejected"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDataCatalogs rejects MaxResults outside its documented 2-50 range with
    InvalidRequestException instead of clamping it, and accepts MaxResults=2."""
    # Client-side parameter validation would otherwise short-circuit this before it ever
    # reaches the wire (MaxResults carries a min:2/max:50 range constraint in the model),
    # so use a client with validation disabled to actually exercise the server-side rejection.
    athena = _unvalidated_client(ctx, "athena")

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    catalog = ctx.unique_name("sim2real-athena-ldc-")
    athena.create_data_catalog(
        Name=catalog,
        Type="GLUE",
        Parameters={"catalog-id": account_id},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_data_catalog(Name=catalog))

    below_min_code, below_min_message = _error(lambda: athena.list_data_catalogs(MaxResults=1))
    assert below_min_code == "InvalidRequestException", (
        f"expected InvalidRequestException for MaxResults=1 (below the documented minimum of 2), "
        f"got {below_min_code!r}"
    )
    assert below_min_message == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 2"
    ), f"unexpected ListDataCatalogs message: {below_min_message!r}"

    above_max_code, above_max_message = _error(lambda: athena.list_data_catalogs(MaxResults=51))
    assert above_max_code == "InvalidRequestException", (
        f"expected InvalidRequestException for MaxResults=51 (above the documented maximum of "
        f"50), got {above_max_code!r}"
    )
    assert above_max_message == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 50"
    ), f"unexpected ListDataCatalogs message: {above_max_message!r}"

    # The built-in AwsDataCatalog plus the one just created mean at least 2 catalogs exist, so
    # the documented minimum of 2 is accepted and fills a full page of exactly 2 entries.
    resp = athena.list_data_catalogs(MaxResults=2)
    assert len(resp["DataCatalogsSummary"]) == 2, (
        f"expected exactly 2 entries for MaxResults=2 with at least 2 catalogs present, got "
        f"{resp['DataCatalogsSummary']!r}"
    )


def _unvalidated_client(ctx, service: str):
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    instead: accepting a call AWS refuses is a distinct failure, not an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
