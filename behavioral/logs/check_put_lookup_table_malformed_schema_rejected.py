"""put-lookup-table-malformed-schema-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-lookup-table-malformed-schema-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLookupTable rejects a tableBody whose header row declares the same
    column name twice as ValidationException, no lookup table is created, and a
    well-formed CSV with a well-formed header still succeeds."""
    logs = ctx.client("logs")
    bad_name = ctx.unique_name("sim2real_behav_plt_bad_").replace("-", "_")

    # Header declares the same column name twice ("key" appears twice) -- a
    # malformed key/value schema definition, distinct from a CSV-syntax error.
    # Confirmed against real AWS: a column-COUNT mismatch between the header and
    # a data row is accepted (not rejected), so that shape is not usable here --
    # the duplicate-header-name shape below is the one AWS actually rejects.
    malformed_body = "key,key\nuser_id,active\n"

    code, message = _client_error(
        logs, lambda: logs.create_lookup_table(lookupTableName=bad_name, tableBody=malformed_body)
    )
    assert code == "ValidationException", f"expected ValidationException for a duplicate CSV header field name, got {code!r}"
    assert message == "CSV header contains duplicate field names", f"unexpected message: {message!r}"

    # (b) effect absent: no lookup table with that name exists
    tables = logs.describe_lookup_tables().get("lookupTables", [])
    assert bad_name not in {t.get("lookupTableName") for t in tables}, (
        f"rejected table {bad_name!r} unexpectedly appears in DescribeLookupTables"
    )

    # (c) positive control: a well-formed CSV (no duplicate header fields) is accepted.
    good_name = ctx.unique_name("sim2real_behav_plt_good_").replace("-", "_")
    good_body = "key,value\nuser_id,active\n"
    resp = logs.create_lookup_table(
        lookupTableName=good_name, tableBody=good_body, tags={"Sim2RealOwner": "behavioral-suite"}
    )
    ctx.on_cleanup(lambda: logs.delete_lookup_table(lookupTableArn=resp["lookupTableArn"]))
    assert resp["lookupTableArn"], f"expected a non-empty lookupTableArn, got {resp.get('lookupTableArn')!r}"
    tables = logs.describe_lookup_tables().get("lookupTables", [])
    assert good_name in {t.get("lookupTableName") for t in tables}, (
        f"expected {good_name!r} in DescribeLookupTables, got names={[t.get('lookupTableName') for t in tables]!r}"
    )


def _client_error(logs, fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises rather than returning a
    falsy sentinel, because real AWS accepting input the check expects rejected is the strongest
    signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    arn = result.get("lookupTableArn")
    if arn:
        logs.delete_lookup_table(lookupTableArn=arn)
    raise AssertionError(f"expected CreateLookupTable to reject the malformed body, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
