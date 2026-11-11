"""list-named-queries-reflects-live-creation-deletion."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-named-queries-reflects-live-creation-deletion"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListNamedQueries is a live view that includes a named query immediately
    after CreateNamedQuery and excludes it immediately after DeleteNamedQuery."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-namedquery-")

    before_ids = set(_named_query_ids(athena))

    created = athena.create_named_query(Name=name, Database="default", QueryString="SELECT 1")
    nqid = created["NamedQueryId"]
    ctx.on_cleanup(lambda: _safe_delete_named_query(athena, nqid))

    assert nqid not in before_ids, f"freshly created NamedQueryId {nqid!r} already present before creation"

    after_create_ids = set(_named_query_ids(athena))
    assert nqid in after_create_ids, "named query missing from ListNamedQueries immediately after creation"

    fetched = athena.get_named_query(NamedQueryId=nqid)["NamedQuery"]
    assert fetched["Name"] == name, f"expected Name {name!r}, got {fetched['Name']!r}"
    assert fetched["QueryString"] == "SELECT 1", f"expected QueryString 'SELECT 1', got {fetched['QueryString']!r}"

    athena.delete_named_query(NamedQueryId=nqid)
    after_delete_ids = set(_named_query_ids(athena))
    assert nqid not in after_delete_ids, "deleted named query still present in ListNamedQueries"

    code, message = _error(lambda: athena.get_named_query(NamedQueryId=nqid))
    assert code == "InvalidRequestException", f"expected InvalidRequestException reading deleted named query, got {code}"
    assert message == f"NamedQuery: {nqid} does not exist", f"unexpected GetNamedQuery message: {message!r}"

    code2, message2 = _error(lambda: athena.delete_named_query(NamedQueryId=nqid))
    assert code2 == "InvalidRequestException", f"expected InvalidRequestException deleting already-deleted named query, got {code2}"
    assert message2 == f"NamedQuery: {nqid} does not exist", f"unexpected DeleteNamedQuery message: {message2!r}"


def _named_query_ids(athena):
    out = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = athena.list_named_queries(**kwargs)
        out.extend(resp["NamedQueryIds"])
        token = resp.get("NextToken")
        if not token:
            break
    return out


def _safe_delete_named_query(athena, nqid):
    try:
        athena.delete_named_query(NamedQueryId=nqid)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err.get("Code") == "InvalidRequestException" and "does not exist" in err.get("Message", "")):
            raise


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
