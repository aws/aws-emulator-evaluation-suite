"""geometric-and-money-literals-each-print-the-engines-normalized-form."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "geometric-and-money-literals-each-print-the-engines-normalized-form"
GROUP = "data-plane"
SERVICES = ["redshift-data", "redshift-serverless"]

# One SELECT per literal: each statement returns a single column, so GetStatementResult's
# ColumnMetadata and the one cell it carries are about that literal alone. `printed` is the
# engine's own normalized form of the value, recorded from a real run, never the SQL's literal
# text.
_LITERALS = [
    ("point", "SELECT point(3, 4)", "(3.0,4.0)"),
    ("box", "SELECT box '((2,3),(9,7))'", "(9.0,7.0),(2.0,3.0)"),
    ("circle", "SELECT circle '<(5,6),4>'", "<(5.0,6.0),4.0>"),
    ("lseg", "SELECT lseg '[(1,2),(8,9)]'", "[(1.0,2.0),(8.0,9.0)]"),
    ("path", "SELECT path '[(1,1),(4,2),(6,5)]'", "[(1,1),(4,2),(6,5)]"),
    ("polygon", "SELECT polygon '((0,0),(4,0),(4,3),(0,3))'", "((0.0,0.0),(4.0,0.0),(4.0,3.0),(0.0,3.0))"),
    ("money", "SELECT '256.78'::money", 256.78),
]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Each of six geometric literals and a money cast runs as its own ExecuteStatement.

    GetStatementResult names the type in ColumnMetadata's typeName and the one cell holds the
    engine's own printed form of the value, never the literal text the SQL carried.
    """
    rd = ctx.client("redshift-data")
    wg = _provision(ctx)

    for type_name, sql, expected_printed in _LITERALS:
        sid = _run_to_terminal(rd, wg, sql)
        result = rd.get_statement_result(Id=sid)
        columns = result["ColumnMetadata"]
        assert len(columns) == 1, f"{sql!r} returned {len(columns)} columns, expected 1: {columns!r}"
        assert columns[0]["typeName"] == type_name, (
            f"{sql!r}: ColumnMetadata typeName was {columns[0]['typeName']!r}, expected {type_name!r}"
        )
        cell = result["Records"][0][0]
        if type_name == "money":
            printed = cell.get("doubleValue")
        else:
            printed = cell.get("stringValue")
        assert printed == expected_printed, (
            f"{sql!r}: cell printed {printed!r}, expected the engine's normalized "
            f"{expected_printed!r}"
        )


# ===== self-contained helpers =====


def _run_to_terminal(rd, workgroup, sql, *, timeout_s=120, interval_s=2.0):
    sid = rd.execute_statement(WorkgroupName=workgroup, Database="dev", Sql=sql)["Id"]
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = rd.describe_statement(Id=sid)
        if desc["Status"] in ("FINISHED", "FAILED", "ABORTED"):
            break
        time.sleep(interval_s)
    else:
        raise AssertionError(f"statement {sid} ({sql!r}) did not reach a terminal status within {timeout_s}s")
    assert desc["Status"] == "FINISHED", (
        f"{sql!r} ended {desc['Status']!r}: {desc.get('Error')!r}"
    )
    assert desc["HasResultSet"] is True, f"{sql!r} finished with no result set: {desc!r}"
    return sid


def _resource_status(describe, extract):
    """``extract`` applied to ``describe()``'s result, or ``None`` once the resource is gone."""
    try:
        return extract(describe())
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _await(probe, target, *, timeout_s, interval_s, label):
    deadline = time.monotonic() + timeout_s
    seen = None
    while time.monotonic() < deadline:
        seen = probe()
        if seen == target:
            return seen
        time.sleep(interval_s)
    raise AssertionError(f"{label} never reached {target!r}; last observed {seen!r}")


def _delete_until_gone(delete, probe, *, timeout_s, interval_s, label):
    """Reissue ``delete`` until it is accepted, then wait for ``probe`` to report absence.

    A namespace or workgroup still settling answers a delete with ``ConflictException``, so one
    call is not a teardown; a not-found on either the delete or the probe means it is gone.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if time.monotonic() >= deadline:
                raise AssertionError(f"{label}: delete kept failing ({exc.response['Error']['Code']})")
            time.sleep(interval_s)
    _await(lambda: probe() is None, True, timeout_s=max(1.0, deadline - time.monotonic()),
           interval_s=interval_s, label=f"{label} absent")


def _provision(ctx) -> str:
    rss = ctx.client("redshift-serverless")
    ns = ctx.unique_name("sim2real-rdmoney-ns-")
    wg = ctx.unique_name("sim2real-rdmoney-wg-")

    rss.create_namespace(namespaceName=ns, dbName="dev", tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: rss.delete_namespace(namespaceName=ns),
        lambda: _resource_status(lambda: rss.get_namespace(namespaceName=ns),
                                  lambda r: r["namespace"]["status"]),
        timeout_s=600, interval_s=10, label=f"namespace {ns}",
    ))
    _await(lambda: _resource_status(lambda: rss.get_namespace(namespaceName=ns),
                                     lambda r: r["namespace"]["status"]),
           "AVAILABLE", timeout_s=300, interval_s=5, label=f"namespace {ns}")

    rss.create_workgroup(
        workgroupName=wg, namespaceName=ns, baseCapacity=8, publiclyAccessible=False,
        subnetIds=ctx.network().subnet_ids, tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: rss.delete_workgroup(workgroupName=wg),
        lambda: _resource_status(lambda: rss.get_workgroup(workgroupName=wg),
                                  lambda r: r["workgroup"]["status"]),
        timeout_s=600, interval_s=10, label=f"workgroup {wg}",
    ))
    _await(lambda: _resource_status(lambda: rss.get_workgroup(workgroupName=wg),
                                     lambda r: r["workgroup"]["status"]),
           "AVAILABLE", timeout_s=900, interval_s=15, label=f"workgroup {wg}")
    return wg


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
