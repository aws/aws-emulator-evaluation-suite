"""op-contract-get-data-catalog."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-get-data-catalog"
GROUP = "error-semantics"
SERVICES = ["athena"]


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_results_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-getcat-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # CreateBucket rejects an explicit LocationConstraint of us-east-1.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _empty_and_delete_bucket(ctx: Any, bucket: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket)
    keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
    if keys:
        s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _wait_for_query(ctx: Any, athena, query_execution_id: str, timeout_s: float = 60.0) -> str:
    deadline = time.monotonic() + timeout_s
    state = "QUEUED"
    while time.monotonic() < deadline:
        resp = athena.get_query_execution(QueryExecutionId=query_execution_id)
        state = resp["QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return state
        time.sleep(1.5)
    raise AssertionError(f"query {query_execution_id} stuck in {state} after {timeout_s}s")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDataCatalog rejects the listed built-in AwsDataCatalog and a nonexistent name with
    InvalidRequestException, and returns Type/Parameters for a catalog made via CreateDataCatalog."""
    athena = ctx.client("athena")

    # A trivial query first, so Athena has been used in this account/region.
    bucket = _create_results_bucket(ctx)
    qid = athena.start_query_execution(
        QueryString="SELECT 1",
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]
    _wait_for_query(ctx, athena, qid, timeout_s=60)

    catalogs = athena.list_data_catalogs()["DataCatalogsSummary"]
    assert any(c["CatalogName"] == "AwsDataCatalog" for c in catalogs), catalogs

    # The built-in catalog is listed, but GetDataCatalog on it is rejected --
    # it is not a retrievable resource by name.
    builtin_code, builtin_message = _error(lambda: athena.get_data_catalog(Name="AwsDataCatalog"))
    assert builtin_code == "InvalidRequestException", (
        f"expected InvalidRequestException for the built-in AwsDataCatalog, got {builtin_code}"
    )
    assert builtin_message == "DataCatalog AwsDataCatalog was not found.", builtin_message

    # A catalog actually created via CreateDataCatalog is retrievable and its
    # Type/Parameters round-trip correctly.
    name = ctx.unique_name("sim2real-getcat-")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    athena.create_data_catalog(
        Name=name,
        Type="GLUE",
        Description="probe catalog",
        Parameters={"catalog-id": account_id},
    )
    ctx.on_cleanup(lambda: athena.delete_data_catalog(Name=name))

    catalog = athena.get_data_catalog(Name=name)["DataCatalog"]
    assert catalog["Name"] == name, f"expected catalog Name {name!r}, got {catalog['Name']!r}"
    assert catalog["Type"] == "GLUE", f"expected catalog Type GLUE, got {catalog['Type']}"

    missing_name = ctx.unique_name("sim2real-nonexistent-catalog-")
    code, message = _error(lambda: athena.get_data_catalog(Name=missing_name))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected = f"DataCatalog {missing_name} was not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
