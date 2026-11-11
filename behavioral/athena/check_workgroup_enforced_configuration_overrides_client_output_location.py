"""workgroup-enforced-configuration-overrides-client-output-location."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "workgroup-enforced-configuration-overrides-client-output-location"
GROUP = "server-side"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With EnforceWorkGroupConfiguration on, a client OutputLocation is ignored and results land in
    the workgroup's location; with it off, the client's location is used. Object counts confirm where
    the bytes landed."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    wg_name = ctx.unique_name("sim2real-athena-wg-")
    wg_prefix = f"s3://{bucket}/wg-output/"
    client_prefix = f"s3://{bucket}/client-output/"

    athena.create_work_group(
        Name=wg_name,
        Configuration={
            "ResultConfiguration": {"OutputLocation": wg_prefix},
            "EnforceWorkGroupConfiguration": True,
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    exec_id = athena.start_query_execution(
        QueryString="SELECT 1",
        WorkGroup=wg_name,
        ResultConfiguration={"OutputLocation": client_prefix},
    )["QueryExecutionId"]

    state = _poll_until(
        lambda: athena.get_query_execution(QueryExecutionId=exec_id)["QueryExecution"]["Status"]["State"],
        lambda s: s in ("SUCCEEDED", "FAILED", "CANCELLED"),
        timeout_s=120,
        interval_s=3,
    )
    assert state == "SUCCEEDED", f"query did not succeed, state={state}"

    execution = athena.get_query_execution(QueryExecutionId=exec_id)["QueryExecution"]
    actual_location = execution["ResultConfiguration"]["OutputLocation"]
    assert actual_location.startswith(wg_prefix), (
        f"expected the workgroup-enforced location {wg_prefix!r} to win, "
        f"got {actual_location!r}"
    )
    assert not actual_location.startswith(client_prefix), (
        "client-supplied output location leaked through despite EnforceWorkGroupConfiguration"
    )
    assert _object_count(s3, bucket, "wg-output/") > 0, (
        "no result object was actually written under the enforced workgroup prefix"
    )
    assert _object_count(s3, bucket, "client-output/") == 0, (
        "a result object was written under the client-chosen prefix despite enforcement"
    )

    # The flag must actually be consulted, not just always-ignore the client value: flip it
    # off and demand the client's location win instead.
    athena.update_work_group(
        WorkGroup=wg_name, ConfigurationUpdates={"EnforceWorkGroupConfiguration": False}
    )
    assert (
        athena.get_work_group(WorkGroup=wg_name)["WorkGroup"]["Configuration"][
            "EnforceWorkGroupConfiguration"
        ]
        is False
    ), "EnforceWorkGroupConfiguration did not read back False after update_work_group"

    exec_id2 = athena.start_query_execution(
        QueryString="SELECT 2",
        WorkGroup=wg_name,
        ResultConfiguration={"OutputLocation": client_prefix},
    )["QueryExecutionId"]
    state2 = _poll_until(
        lambda: athena.get_query_execution(QueryExecutionId=exec_id2)["QueryExecution"]["Status"]["State"],
        lambda s: s in ("SUCCEEDED", "FAILED", "CANCELLED"),
        timeout_s=120,
        interval_s=3,
    )
    assert state2 == "SUCCEEDED", f"query did not succeed, state={state2}"

    execution2 = athena.get_query_execution(QueryExecutionId=exec_id2)["QueryExecution"]
    actual_location2 = execution2["ResultConfiguration"]["OutputLocation"]
    assert actual_location2.startswith(client_prefix), (
        f"with EnforceWorkGroupConfiguration=false the client location {client_prefix!r} must "
        f"be used, got {actual_location2!r}"
    )
    assert _object_count(s3, bucket, "client-output/") > 0, (
        "with enforcement off the query results must actually appear under the client prefix"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _object_count(s3, bucket, prefix):
    n = 0
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        n += len(page.get("Contents", []))
    return n


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-athena-out-").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
