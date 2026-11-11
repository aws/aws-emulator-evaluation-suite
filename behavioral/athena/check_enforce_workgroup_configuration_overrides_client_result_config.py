"""enforce-workgroup-configuration-overrides-client-result-config."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "enforce-workgroup-configuration-overrides-client-result-config"
GROUP = 'workgroup'
SERVICES = ['athena']


def _empty_and_delete_bucket(s3, bucket):
    """Empty then delete a bucket; Athena writes its own result artifacts into it."""
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "enforce-workgroup-configuration-overrides-client-result-config"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket





def _wait_terminal(athena, qid, timeout_s=300, interval_s=2):
    """Poll GetQueryExecution to a terminal state; a cold engine slot can take minutes."""
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")






def _object_count(s3, bucket, prefix):
    n = 0
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        n += len(page.get("Contents", []))
    return n

@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")

def run(ctx) -> None:
    """EnforceWorkGroupConfiguration=true silently overrides a client ResultConfiguration (results
    land in the enforced bucket, the client's stays empty); setting it false hands control back.
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")

    enforced_bucket = _make_bucket(ctx, "sim2real-behav-athena-enforced-")
    enforced_out = f"s3://{enforced_bucket}/enforced/"
    client_bucket = _make_bucket(ctx, "sim2real-behav-athena-client-")
    client_out = f"s3://{client_bucket}/clientchosen/"

    wg = ctx.unique_name("sim2real-behav-wg-enforce-")
    athena.create_work_group(
        Name=wg,
        Configuration={
            "ResultConfiguration": {"OutputLocation": enforced_out},
            "EnforceWorkGroupConfiguration": True,
        },
        Tags=[{"Key": "sim2real", "Value": "enforce-workgroup-configuration-overrides-client-result-config"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    # --- control: no client ResultConfiguration -> the workgroup default is used ---
    base_qid = athena.start_query_execution(QueryString="SELECT 1 AS a", WorkGroup=wg)[
        "QueryExecutionId"
    ]
    assert _wait_terminal(athena, base_qid) == "SUCCEEDED"
    base_loc = athena.get_query_execution(QueryExecutionId=base_qid)["QueryExecution"][
        "ResultConfiguration"
    ]["OutputLocation"]
    assert base_loc.startswith(enforced_out), (
        f"baseline query must write to the workgroup default {enforced_out!r}, got {base_loc!r}"
    )

    # The conflicting client location is silently overridden, not rejected.
    qid = athena.start_query_execution(
        QueryString="SELECT 2 AS a",
        WorkGroup=wg,
        ResultConfiguration={"OutputLocation": client_out},
    )["QueryExecutionId"]
    assert _wait_terminal(athena, qid) == "SUCCEEDED"
    effective = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"][
        "ResultConfiguration"
    ]["OutputLocation"]
    assert effective.startswith(enforced_out), (
        f"with EnforceWorkGroupConfiguration=true the enforced location {enforced_out!r} must "
        f"win over the client's {client_out!r}; effective location was {effective!r}"
    )
    assert client_bucket not in effective, (
        f"the client-supplied bucket must not appear in the effective location: {effective!r}"
    )
    leaked = _object_count(s3, client_bucket, "clientchosen/")
    assert leaked == 0, (
        f"{leaked} result object(s) were written to the client-chosen prefix despite "
        f"EnforceWorkGroupConfiguration=true — the enforced results location is not enforced"
    )

    athena.update_work_group(
        WorkGroup=wg, ConfigurationUpdates={"EnforceWorkGroupConfiguration": False}
    )
    assert (
        athena.get_work_group(WorkGroup=wg)["WorkGroup"]["Configuration"][
            "EnforceWorkGroupConfiguration"
        ]
        is False
    )
    qid2 = athena.start_query_execution(
        QueryString="SELECT 3 AS a",
        WorkGroup=wg,
        ResultConfiguration={"OutputLocation": client_out},
    )["QueryExecutionId"]
    assert _wait_terminal(athena, qid2) == "SUCCEEDED"
    effective2 = athena.get_query_execution(QueryExecutionId=qid2)["QueryExecution"][
        "ResultConfiguration"
    ]["OutputLocation"]
    assert effective2.startswith(client_out), (
        f"with EnforceWorkGroupConfiguration=false the client location {client_out!r} must be "
        f"used, got {effective2!r}"
    )
    assert _object_count(s3, client_bucket, "clientchosen/") > 0, (
        "with enforcement off the query results must actually appear under the client prefix"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
