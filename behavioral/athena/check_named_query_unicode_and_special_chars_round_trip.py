"""named-query-unicode-and-special-chars-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "named-query-unicode-and-special-chars-round-trip"
GROUP = "representation"
SERVICES = ["athena"]


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A named query created with unicode + SQL special characters in its
    Description/QueryString is returned byte-for-byte identical by GetNamedQuery,
    and once deleted is gone by an independent read and no longer mutable.
    """
    athena = ctx.client("athena")

    name = ctx.unique_name("sim2real-nq-")
    # "default" is Athena's built-in database that exists in every account/region
    # without any prior Glue/DDL setup.
    database = "default"
    query_string = (
        "SELECT 'héllo \"wörld\" — 日本語 % _ \\n tab\\t ''quoted'' back\\\\slash' "
        "AS greeting -- trailing comment\n"
        "/* block comment with unicode: 中文 */"
    )
    description = (
        "Ünïcödé déscription with 'single', \"double\" quotes, "
        "a % wildcard, a _ underscore, a semicolon; and emoji 🚀日本語"
    )

    created = athena.create_named_query(
        Name=name,
        Database=database,
        QueryString=query_string,
        Description=description,
    )
    named_query_id = created["NamedQueryId"]
    ctx.on_cleanup(lambda: _delete_if_present(athena, named_query_id))

    got = athena.get_named_query(NamedQueryId=named_query_id)["NamedQuery"]

    assert got["Name"] == name
    assert got["Database"] == database
    assert got["QueryString"] == query_string, (
        f"QueryString mismatch:\nexpected={query_string!r}\nactual={got['QueryString']!r}"
    )
    assert got["Description"] == description, (
        f"Description mismatch:\nexpected={description!r}\nactual={got['Description']!r}"
    )

    athena.delete_named_query(NamedQueryId=named_query_id)

    gone = ("InvalidRequestException", f"NamedQuery: {named_query_id} does not exist")
    got = _error(lambda: athena.get_named_query(NamedQueryId=named_query_id))
    assert got == gone, f"expected {gone} reading a deleted named query, got {got!r}"

    second_delete = _error(lambda: athena.delete_named_query(NamedQueryId=named_query_id))
    assert second_delete == gone, (
        f"expected {gone} deleting an already-deleted named query, got {second_delete!r}"
    )


def _delete_if_present(athena, nq_id):
    """Teardown: the body deletes the query itself, so an already-gone id is not a failure."""
    from botocore.exceptions import ClientError

    try:
        athena.delete_named_query(NamedQueryId=nq_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidRequestException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
