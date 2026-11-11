"""op-contract-deleteNamedQuery."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteNamedQuery"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteNamedQuery removes the query so a subsequent GetNamedQuery fails, and
    deleting an already-deleted NamedQueryId raises InvalidRequestException."""
    athena = ctx.client("athena")

    name = ctx.unique_name("sim2real-athena-nq-")
    qid = athena.create_named_query(
        Name=name, Database="default", QueryString="SELECT 1", WorkGroup="primary"
    )["NamedQueryId"]
    ctx.on_cleanup(lambda: _safe_delete(athena, qid))

    # Exists before delete.
    got = athena.get_named_query(NamedQueryId=qid)["NamedQuery"]
    assert got["Name"] == name, f"expected {name!r}, got {got['Name']!r}"

    athena.delete_named_query(NamedQueryId=qid)

    code, message = _error(lambda: athena.get_named_query(NamedQueryId=qid))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == f"NamedQuery: {qid} does not exist", message

    # Error boundary: deleting the same, now-nonexistent id again is rejected.
    code2, message2 = _error(lambda: athena.delete_named_query(NamedQueryId=qid))
    assert code2 == "InvalidRequestException", f"expected InvalidRequestException, got {code2}"
    assert message2 == f"NamedQuery: {qid} does not exist", message2


def _error(fn):
    """Call fn(); return the botocore error (code, message). A success raises: AWS rejects this
    call, and accepting it is a distinct failure from returning the wrong error code."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _safe_delete(athena, qid: str) -> None:
    try:
        athena.delete_named_query(NamedQueryId=qid)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err.get("Code") == "InvalidRequestException" and "does not exist" in err.get("Message", "")):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
