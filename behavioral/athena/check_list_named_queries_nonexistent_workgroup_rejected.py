"""list-named-queries-nonexistent-workgroup-rejected."""
from __future__ import annotations

from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-named-queries-nonexistent-workgroup-rejected"
GROUP = "ordering"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListNamedQueries scoped to a real workgroup returns the named query created in
    it (positive control); scoped to a WorkGroup name that does not exist, Athena
    rejects the call with InvalidRequestException rather than returning an empty list."""
    athena = ctx.client("athena")

    wg_name = ctx.unique_name("sim2real-wg-")
    athena.create_work_group(Name=wg_name)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name))

    nq_name = ctx.unique_name("sim2real-nq-")
    resp = athena.create_named_query(
        Name=nq_name, Database="default", QueryString="SELECT 1", WorkGroup=wg_name
    )
    nq_id = resp["NamedQueryId"]
    ctx.on_cleanup(lambda: athena.delete_named_query(NamedQueryId=nq_id))

    # positive control: the real workgroup lists our named query
    positive = athena.list_named_queries(WorkGroup=wg_name)
    assert nq_id in positive.get("NamedQueryIds", []), "expected named query visible in its own workgroup"

    # negative: a workgroup name that does not exist is rejected, not silently empty
    bogus_wg = ctx.unique_name("sim2real-nonexistent-wg-")
    code, message = _error(lambda: athena.list_named_queries(WorkGroup=bogus_wg))
    assert code == "InvalidRequestException", f"expected InvalidRequestException for nonexistent workgroup, got {code}"
    assert message == "WorkGroup is not found.", f"unexpected ListNamedQueries message: {message!r}"


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
