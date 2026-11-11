"""workgroup-result-configuration-enforced."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "workgroup-result-configuration-enforced"
GROUP = "data-plane-depth"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With EnforceWorkGroupConfiguration on, queries with no or a conflicting client ResultConfiguration
    write to the workgroup's location with correct results; with it off, the client override is
    honored."""
    bucket = _make_output_bucket(ctx)
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-athena-wg-")
    wg_prefix = f"s3://{bucket}/wgout/"
    client_prefix = f"s3://{bucket}/clientout/"
    athena.create_work_group(
        Name=name,
        Configuration={
            "ResultConfiguration": {"OutputLocation": wg_prefix},
            "EnforceWorkGroupConfiguration": True,
        },
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))

    qid = athena.start_query_execution(QueryString="SELECT 7 AS n", WorkGroup=name)[
        "QueryExecutionId"
    ]
    execution = _wait_for_query(ctx, qid)
    assert execution["Status"]["State"] == "SUCCEEDED", execution["Status"]
    assert execution["ResultConfiguration"]["OutputLocation"].startswith(wg_prefix), execution[
        "ResultConfiguration"
    ]

    results = athena.get_query_results(QueryExecutionId=qid)
    value = results["ResultSet"]["Rows"][1]["Data"][0]["VarCharValue"]
    assert value == "7", f"expected query result '7', got {value!r}"

    # Break exactly one thing: ask for a different, conflicting output location.
    qid_conflict = athena.start_query_execution(
        QueryString="SELECT 8 AS n",
        WorkGroup=name,
        ResultConfiguration={"OutputLocation": client_prefix},
    )["QueryExecutionId"]
    execution_conflict = _wait_for_query(ctx, qid_conflict)
    assert execution_conflict["Status"]["State"] == "SUCCEEDED", execution_conflict["Status"]
    effective = execution_conflict["ResultConfiguration"]["OutputLocation"]
    assert effective.startswith(wg_prefix), (
        f"EnforceWorkGroupConfiguration=True must override the client's ResultConfiguration "
        f"with the workgroup's {wg_prefix!r}; got {effective!r}"
    )
    leaked = s3.list_objects_v2(Bucket=bucket, Prefix="clientout/").get("Contents", [])
    assert not leaked, (
        f"{len(leaked)} object(s) were written to the client-chosen prefix despite "
        f"EnforceWorkGroupConfiguration=True -- the enforced location is not enforced"
    )

    # Restore: with enforcement off, the identical client override must now be honored --
    # proving the flag is actually consulted, not that client overrides are always ignored.
    athena.update_work_group(
        WorkGroup=name, ConfigurationUpdates={"EnforceWorkGroupConfiguration": False}
    )
    refreshed = athena.get_work_group(WorkGroup=name)["WorkGroup"]["Configuration"]
    assert refreshed["EnforceWorkGroupConfiguration"] is False, refreshed

    qid_honored = athena.start_query_execution(
        QueryString="SELECT 9 AS n",
        WorkGroup=name,
        ResultConfiguration={"OutputLocation": client_prefix},
    )["QueryExecutionId"]
    execution_honored = _wait_for_query(ctx, qid_honored)
    assert execution_honored["Status"]["State"] == "SUCCEEDED", execution_honored["Status"]
    effective_honored = execution_honored["ResultConfiguration"]["OutputLocation"]
    assert effective_honored.startswith(client_prefix), (
        f"with EnforceWorkGroupConfiguration=False the client location {client_prefix!r} "
        f"must be used, got {effective_honored!r}"
    )
    landed = s3.list_objects_v2(Bucket=bucket, Prefix="clientout/").get("Contents", [])
    assert landed, (
        "with enforcement off the query results must actually appear under the client prefix"
    )


def _make_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        while objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
            resp = s3.list_objects_v2(Bucket=bucket)
            objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _wait_for_query(ctx, qid, timeout_s=180.0, interval_s=2.0):
    athena = ctx.client("athena")
    terminal = {"SUCCEEDED", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = athena.get_query_execution(QueryExecutionId=qid)
        last = resp["QueryExecution"]
        if last["Status"]["State"] in terminal:
            return last
        time.sleep(interval_s)
    state = last["Status"]["State"] if last else None
    raise AssertionError(f"query {qid} did not reach terminal state within {timeout_s}s (last={state})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
