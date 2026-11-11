"""concurrent-data-catalog-delete-only-one-succeeds."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-data-catalog-delete-only-one-succeeds"
GROUP = "concurrency"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent DeleteDataCatalog calls on one catalog never both fail (AWS does not serialize
    them, so both often succeed), a losing call reports InvalidRequestException not found, and an
    independent read confirms the catalog is gone."""
    athena = ctx.client("athena")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-athena-cat-")
    athena.create_data_catalog(
        Name=name,
        Type="GLUE",
        Parameters={"catalog-id": account_id},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    cleaned_up = {"done": False}

    def _cleanup():
        if cleaned_up["done"]:
            return
        try:
            athena.delete_data_catalog(Name=name)
        except ClientError as exc:
            if "not found" not in exc.response["Error"].get("Message", ""):
                raise

    ctx.on_cleanup(_cleanup)

    def _delete():
        try:
            athena.delete_data_catalog(Name=name)
            return ("ok", None)
        except ClientError as exc:
            return ("error", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _delete(), range(2)))
    cleaned_up["done"] = True

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]
    assert len(successes) >= 1, f"expected at least one delete to succeed, got {results}"
    # A losing delete meets a catalog the winner already removed. AWS's delete-path not-found
    # message carries no trailing period, unlike the GetDataCatalog one below.
    expected_loss = ("InvalidRequestException", f"DataCatalog {name} was not found")
    bad = [err for _, err in failures if err != expected_loss]
    assert not bad, f"unexpected error(s) on the losing side: {bad} ({results})"

    # effect: the catalog is really gone, not left in a half-deleted or duplicated state
    try:
        got = athena.get_data_catalog(Name=name)
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    else:
        raise AssertionError(f"GetDataCatalog after the racing deletes SUCCEEDED and returned {got!r}")
    assert code == "InvalidRequestException", code
    assert message == f"DataCatalog {name} was not found.", repr(message)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
