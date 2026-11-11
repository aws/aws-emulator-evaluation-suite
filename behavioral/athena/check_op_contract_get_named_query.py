"""op-contract-getNamedQuery."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getNamedQuery"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetNamedQuery returns the exact Name/Database/QueryString/WorkGroup given at creation; a
    well-formed but nonexistent NamedQueryId raises InvalidRequestException, and so does the same
    call once the query is actually deleted."""
    athena = ctx.client("athena")

    name = ctx.unique_name("sim2real-athena-nq-")
    query = "SELECT 42 AS answer"
    qid = athena.create_named_query(
        Name=name, Database="default", QueryString=query, WorkGroup="primary",
        Description="sim2real behavioral named query",
    )["NamedQueryId"]

    def _cleanup():
        try:
            athena.delete_named_query(NamedQueryId=qid)
        except ClientError as exc:
            # The in-body delete leg below normally removes it first.
            err = exc.response["Error"]
            if not (err.get("Code") == "InvalidRequestException" and "does not exist" in err.get("Message", "")):
                raise

    ctx.on_cleanup(_cleanup)

    got = athena.get_named_query(NamedQueryId=qid)["NamedQuery"]
    assert got["Name"] == name, f"expected Name {name!r}, got {got['Name']!r}"
    assert got["Database"] == "default", f"expected Database 'default', got {got['Database']!r}"
    assert got["QueryString"] == query, f"expected QueryString {query!r}, got {got['QueryString']!r}"
    assert got["WorkGroup"] == "primary", f"expected WorkGroup 'primary', got {got['WorkGroup']!r}"
    assert got["Description"] == "sim2real behavioral named query", (
        f"expected Description 'sim2real behavioral named query', got {got['Description']!r}")
    assert got["NamedQueryId"] == qid, f"expected NamedQueryId {qid!r}, got {got['NamedQueryId']!r}"

    bogus = str(uuid.uuid4())
    code, message = _error(lambda: athena.get_named_query(NamedQueryId=bogus))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected = f"NamedQuery: {bogus} does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    athena.delete_named_query(NamedQueryId=qid)
    code_after_delete, message_after_delete = _error(lambda: athena.get_named_query(NamedQueryId=qid))
    assert code_after_delete == "InvalidRequestException", (
        f"expected InvalidRequestException for a deleted NamedQueryId, got {code_after_delete}")
    expected_after_delete = f"NamedQuery: {qid} does not exist"
    assert message_after_delete == expected_after_delete, (
        f"expected message {expected_after_delete!r}, got {message_after_delete!r}")


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises: AWS
    rejects this call, and accepting it is a distinct failure from returning the wrong error code."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
