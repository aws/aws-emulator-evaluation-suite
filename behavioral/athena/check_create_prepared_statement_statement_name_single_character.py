"""create-prepared-statement-statement-name-single-character."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-prepared-statement-statement-name-single-character"
GROUP = "representation"
SERVICES = ["athena"]


def _error(fn):
    """Call fn() and return its ClientError (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePreparedStatement accepts a 2-character StatementName but refuses a 1-character one,
    even though the operation's own length constraint allows a minimum of 1."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(Name=wg, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    two_char_name = "AB"
    athena.create_prepared_statement(StatementName=two_char_name, WorkGroup=wg, QueryStatement="SELECT 1")
    ctx.on_cleanup(lambda: athena.delete_prepared_statement(StatementName=two_char_name, WorkGroup=wg))

    fetched = athena.get_prepared_statement(StatementName=two_char_name, WorkGroup=wg)["PreparedStatement"]
    assert fetched["StatementName"] == two_char_name, (
        f"expected GetPreparedStatement to echo the 2-character StatementName, got {fetched['StatementName']!r}"
    )

    one_char_name = "A"
    code, message = _error(
        lambda: athena.create_prepared_statement(
            StatementName=one_char_name, WorkGroup=wg, QueryStatement="SELECT 1",
        )
    )
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for a 1-character StatementName, got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value at 'statementName' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-zA-Z_][a-zA-Z0-9_@:]{1,256}"
    ), f"unexpected CreatePreparedStatement message for a 1-character StatementName: {message!r}"

    names = set()
    token = None
    while True:
        kwargs = {"WorkGroup": wg}
        if token:
            kwargs["NextToken"] = token
        page = athena.list_prepared_statements(**kwargs)
        names.update(p["StatementName"] for p in page["PreparedStatements"])
        token = page.get("NextToken")
        if not token:
            break
    assert names == {two_char_name}, (
        f"expected only the accepted 2-character statement in the workgroup, got {sorted(names)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
