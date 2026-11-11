"""e2e-lookup-table-enriches-transformed-log-record."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-lookup-table-enriches-transformed-log-record"
GROUP = "e2e"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetLookupTable returns the exact CSV body and sizeBytes, DescribeLookupTables derives
    tableFields and recordsCount, and after DeleteLookupTable both Get and Update raise
    ResourceNotFoundException."""
    logs = ctx.client("logs")

    table_name = ctx.unique_name("sim2real_behav_lookup_").replace("-", "_")
    account = ctx.client("sts").get_caller_identity()["Account"]
    header = "ip_address,hostname,owner"
    rows = ["10.0.1.5,web-01,team-a", "10.0.2.9,db-01,team-b"]
    csv_body = "\n".join([header, *rows]) + "\n"

    create_resp = logs.create_lookup_table(lookupTableName=table_name, tableBody=csv_body)
    table_arn = create_resp["lookupTableArn"]
    ctx.on_cleanup(lambda: _delete_lookup_table_if_present(ctx, table_arn))

    get_resp = logs.get_lookup_table(lookupTableArn=table_arn)
    assert get_resp["lookupTableName"] == table_name, (
        f"expected lookupTableName {table_name!r}, got {get_resp['lookupTableName']!r}"
    )
    assert get_resp["tableBody"] == csv_body, (
        f"GetLookupTable body did not match what was written: expected {csv_body!r}, "
        f"got {get_resp['tableBody']!r}"
    )
    expected_size = len(csv_body.encode("utf-8"))
    assert get_resp["sizeBytes"] == expected_size, (
        f"expected sizeBytes {expected_size}, got {get_resp['sizeBytes']!r}"
    )

    described = logs.describe_lookup_tables(lookupTableNamePrefix=table_name)["lookupTables"]
    matches = [t for t in described if t["lookupTableArn"] == table_arn]
    assert len(matches) == 1, f"expected exactly one described table, got {matches!r}"
    summary = matches[0]
    expected_fields = ["ip_address", "hostname", "owner"]
    assert summary["tableFields"] == expected_fields, (
        f"expected tableFields {expected_fields!r} derived from the CSV header, "
        f"got {summary['tableFields']!r}"
    )
    assert summary["recordsCount"] == len(rows), (
        f"expected recordsCount {len(rows)} derived from the CSV rows, "
        f"got {summary['recordsCount']!r}"
    )

    logs.delete_lookup_table(lookupTableArn=table_arn)

    code, message = _poll_until_gone(ctx, table_arn, timeout_s=30.0)
    assert code == "ResourceNotFoundException", (
        f"GetLookupTable after DeleteLookupTable returned {code!r}, expected "
        "ResourceNotFoundException"
    )
    assert message == (
        f"Lookup table '{table_name}' not found in account '{account}'"
    ), (
        f"unexpected GetLookupTable message after DeleteLookupTable: {message!r}"
    )

    update_code, update_message = _error(lambda: logs.update_lookup_table(
        lookupTableArn=table_arn, tableBody=csv_body
    ))
    assert update_code == "ResourceNotFoundException", (
        f"UpdateLookupTable on a deleted lookupTableArn returned {update_code!r}, "
        "expected ResourceNotFoundException"
    )
    assert update_message == (
        f"Lookup table '{table_name}' not found in account '{account}'"
    ), (
        f"unexpected UpdateLookupTable message on a deleted lookupTableArn: {update_message!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _delete_lookup_table_if_present(ctx, table_arn: str) -> None:
    logs = ctx.client("logs")
    try:
        logs.delete_lookup_table(lookupTableArn=table_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until_gone(ctx, table_arn: str, timeout_s: float) -> tuple[str, str]:
    """Poll GetLookupTable until it fails with ResourceNotFoundException; return its
    (code, message). Any other error raises, and so does a table still readable at the
    deadline."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            logs.get_lookup_table(lookupTableArn=table_arn)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return code, err.response["Error"].get("Message")
            raise
        time.sleep(2.0)
    raise AssertionError(f"lookup table {table_arn} still readable {timeout_s}s after delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
