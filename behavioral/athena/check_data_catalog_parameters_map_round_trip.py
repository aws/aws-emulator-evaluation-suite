"""data-catalog-parameters-map-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "data-catalog-parameters-map-round-trip"
GROUP = "representation"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A HIVE catalog's Parameters map (a long Lambda ARN and an sdk-version) reads back from
    GetDataCatalog unchanged; after DeleteDataCatalog, GetDataCatalog and UpdateDataCatalog on the
    name fail InvalidRequestException."""
    athena = ctx.client("athena")
    catalog_name = ctx.unique_name("sim2real_behav_cat_")

    long_function_name = "sim2real-behav-athena-metadata-fn-" + ("x_y-9" * 40)
    metadata_function_arn = (
        f"arn:aws:lambda:{ctx.region}:123456789012:function:{long_function_name}"
    )
    sdk_version_value = "1.0"
    parameters = {
        "metadata-function": metadata_function_arn,
        "sdk-version": sdk_version_value,
    }

    athena.create_data_catalog(Name=catalog_name, Type="HIVE", Parameters=parameters)

    from botocore.exceptions import ClientError

    def _cleanup():
        try:
            athena.delete_data_catalog(Name=catalog_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidRequestException":
                raise

    ctx.on_cleanup(_cleanup)

    fetched = athena.get_data_catalog(Name=catalog_name)["DataCatalog"]
    assert fetched["Type"] == "HIVE", f"expected Type HIVE, got {fetched['Type']}"
    fetched_params = fetched["Parameters"]
    assert set(fetched_params.keys()) == set(parameters.keys()), (
        f"parameter keys changed: {sorted(fetched_params.keys())} != {sorted(parameters.keys())}"
    )
    assert fetched_params["metadata-function"] == metadata_function_arn, (
        "large metadata-function ARN value was altered/truncated"
    )
    assert len(fetched_params["metadata-function"]) == len(metadata_function_arn), (
        f"metadata-function length changed: {len(fetched_params['metadata-function'])} != "
        f"{len(metadata_function_arn)}"
    )
    assert fetched_params["sdk-version"] == sdk_version_value, (
        f"expected sdk-version {sdk_version_value!r}, got {fetched_params['sdk-version']!r}"
    )

    athena.delete_data_catalog(Name=catalog_name)
    code, message = _error(lambda: athena.get_data_catalog(Name=catalog_name))
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException reading a deleted catalog, got {code}"
    )
    assert message == f"DataCatalog {catalog_name} was not found.", message
    code, message = _error(
        lambda: athena.update_data_catalog(Name=catalog_name, Type="HIVE", Parameters=parameters)
    )
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException updating a deleted catalog, got {code}"
    )
    assert message == f"DataCatalog {catalog_name} does not exist.", message


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
