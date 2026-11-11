"""athena-workgroup-default-output-location-used-by-query."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "athena-workgroup-default-output-location-used-by-query"
GROUP = "data-plane"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A query started with no per-query OutputLocation lands its results under the workgroup's configured S3 prefix."""
    bucket = _create_result_bucket(ctx)
    prefix = "wg-default-results/"
    athena = ctx.client("athena")
    s3 = ctx.client("s3")

    wg = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(
        Name=wg,
        Configuration={
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/{prefix}"},
            "EnforceWorkGroupConfiguration": True,
        },
        Tags=[{"Key": "sim2real", "Value": "workgroup-default-output-location-used-by-query"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    # No ResultConfiguration passed here: the workgroup's default must be used (EnforceWorkGroupConfiguration=True).
    qid = athena.start_query_execution(QueryString="SELECT 7 AS lucky", WorkGroup=wg)["QueryExecutionId"]
    qe = _wait_query_terminal(ctx, qid, timeout_s=60)
    assert qe["Status"]["State"] == "SUCCEEDED", qe["Status"]
    output_location = qe["ResultConfiguration"]["OutputLocation"]
    assert output_location.startswith(f"s3://{bucket}/{prefix}"), (
        f"expected result location under workgroup default s3://{bucket}/{prefix}, got {output_location!r}"
    )

    key = output_location[len(f"s3://{bucket}/") :]
    obj = s3.get_object(Bucket=bucket, Key=key)
    body = obj["Body"].read().decode("utf-8")
    assert "lucky" in body and "7" in body, f"expected header 'lucky' and value '7' in result body, got {body!r}"


def _create_result_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-athena-res-")
    if ctx.region == "us-east-1":
        # us-east-1 rejects a LocationConstraint on create_bucket; every other region requires one.
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "workgroup-default-output-location-used-by-query"}]},
    )

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _wait_query_terminal(ctx, query_execution_id: str, timeout_s: float = 60.0) -> dict:
    athena = ctx.client("athena")
    terminal = {"SUCCEEDED", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = athena.get_query_execution(QueryExecutionId=query_execution_id)["QueryExecution"]
        if last["Status"]["State"] in terminal:
            return last
        time.sleep(2.0)
    raise AssertionError(f"query {query_execution_id} did not reach a terminal state: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
