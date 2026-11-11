"""server-side-enforced-workgroup-config-overrides-client-request."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "server-side-enforced-workgroup-config-overrides-client-request"
GROUP = "server-side"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A workgroup with EnforceWorkGroupConfiguration=True silently overrides the client's
    StartQueryExecution ResultConfiguration with its own; a workgroup with enforcement off
    honors the client-supplied value instead."""
    athena = ctx.client("athena")
    bucket = _create_bucket(ctx)
    wg_output = f"s3://{bucket}/wg-managed/"
    client_output_ignored = f"s3://{bucket}/client-ignored/"
    client_output_honored = f"s3://{bucket}/client-honored/"

    enforced_wg = ctx.unique_name("sim2real-athena-enforced-")
    athena.create_work_group(
        Name=enforced_wg,
        Configuration={
            "ResultConfiguration": {"OutputLocation": wg_output},
            "EnforceWorkGroupConfiguration": True,
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: athena.delete_work_group(WorkGroup=enforced_wg, RecursiveDeleteOption=True)
    )

    query_id = athena.start_query_execution(
        QueryString="SELECT 1",
        WorkGroup=enforced_wg,
        ResultConfiguration={"OutputLocation": client_output_ignored},
    )["QueryExecutionId"]
    state = _wait_for_query(athena, query_id)
    assert state == "SUCCEEDED", f"enforced-workgroup query ended in {state}"

    execution = athena.get_query_execution(QueryExecutionId=query_id)["QueryExecution"]
    effective_location = execution["ResultConfiguration"]["OutputLocation"]
    assert effective_location.startswith(wg_output), (
        f"expected the enforced workgroup's own output location, got {effective_location!r}"
    )
    assert not effective_location.startswith(client_output_ignored), (
        "client-supplied output location must not have been used"
    )
    # Independent side-channel: GetQueryExecution's own ResultConfiguration field is fed by
    # the same request path that could be faked; the client's declared prefix must also be
    # physically empty in S3, not just absent from the API's self-report.
    leaked = _object_count(ctx, bucket, "client-ignored/")
    assert leaked == 0, (
        f"{leaked} object(s) landed under the client-ignored prefix despite "
        "EnforceWorkGroupConfiguration=True — the enforced location is not actually enforced"
    )

    # Contrast: a workgroup WITHOUT enforcement honors the client-supplied location, proving
    # the override above is a real effect of EnforceWorkGroupConfiguration and not a stub that
    # always ignores client-side ResultConfiguration.
    open_wg = ctx.unique_name("sim2real-athena-open-")
    athena.create_work_group(
        Name=open_wg,
        Configuration={
            "ResultConfiguration": {"OutputLocation": wg_output},
            "EnforceWorkGroupConfiguration": False,
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=open_wg, RecursiveDeleteOption=True))

    query_id2 = athena.start_query_execution(
        QueryString="SELECT 1",
        WorkGroup=open_wg,
        ResultConfiguration={"OutputLocation": client_output_honored},
    )["QueryExecutionId"]
    state2 = _wait_for_query(athena, query_id2)
    assert state2 == "SUCCEEDED", f"non-enforced-workgroup query ended in {state2}"

    execution2 = athena.get_query_execution(QueryExecutionId=query_id2)["QueryExecution"]
    effective_location2 = execution2["ResultConfiguration"]["OutputLocation"]
    assert effective_location2.startswith(client_output_honored), (
        f"expected the client-supplied output location, got {effective_location2!r}"
    )
    # Same side-channel as above, other polarity: with enforcement off, the result must
    # actually land under the client's honored prefix, not merely be reported as such.
    honored_count = _object_count(ctx, bucket, "client-honored/")
    assert honored_count > 0, (
        "with EnforceWorkGroupConfiguration=False the query result must actually be written "
        "under the client-supplied prefix"
    )


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # CreateBucket rejects an explicit LocationConstraint matching the (implicit) default
        # region us-east-1; every other region requires it. Not a region pin.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                )
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _object_count(ctx, bucket, prefix):
    s3 = ctx.client("s3")
    n = 0
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        n += len(page.get("Contents", []))
    return n


def _wait_for_query(athena, query_execution_id, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=query_execution_id)["QueryExecution"][
            "Status"
        ]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"query {query_execution_id} did not reach a terminal state within {timeout_s}s "
        f"(last={state})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
