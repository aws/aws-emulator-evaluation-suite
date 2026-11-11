"""athena-list-databases-reflects-glue-database-positive."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "athena-list-databases-reflects-glue-database-positive"
GROUP = "metastore-binding"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A database created directly via glue.create_database becomes visible in Athena's ListDatabases."""
    glue = ctx.client("glue")
    db = ctx.unique_name("sim2real_ga_listdb_").replace("-", "_").lower()
    glue.create_database(DatabaseInput={"Name": db}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db))

    athena = ctx.client("athena")
    names = _poll_until(
        lambda: _list_database_names(athena),
        lambda ns: db in ns,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert db in names, f"{db} not present in Athena list_databases output: {names}"


def _list_database_names(athena) -> list:
    names = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"CatalogName": "AwsDataCatalog"}
        if token:
            kwargs["NextToken"] = token
        resp = athena.list_databases(**kwargs)
        names.extend(d["Name"] for d in resp.get("DatabaseList", []))
        token = resp.get("NextToken")
        if not token:
            break
    return names


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    if predicate(last):
        return last
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
