"""deploy-workgroup-cfn-then-query-honors-config."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-workgroup-cfn-then-query-honors-config"
GROUP = "deploy"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A WorkGroup deployed via CloudFormation with EnforceWorkGroupConfiguration=true
    actually overrides a StartQueryExecution caller's conflicting output location with
    the workgroup's configured S3 location -- not merely a CREATE_COMPLETE stack."""
    s3 = ctx.client("s3")
    enforced_bucket = _create_bucket(ctx, "enforced")
    requested_bucket = _create_bucket(ctx, "requested")

    wg_name = ctx.unique_name("sim2real-behav-wg-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "WG": {
                    "Type": "AWS::Athena::WorkGroup",
                    "Properties": {
                        "Name": wg_name,
                        "RecursiveDeleteOption": True,
                        "WorkGroupConfiguration": {
                            "ResultConfiguration": {
                                "OutputLocation": f"s3://{enforced_bucket}/"
                            },
                            "EnforceWorkGroupConfiguration": True,
                            "PublishCloudWatchMetricsEnabled": False,
                        },
                    },
                }
            },
        }
    )
    _deploy_cfn(ctx, stack_name, template)

    athena = ctx.client("athena")
    wg = athena.get_work_group(WorkGroup=wg_name)["WorkGroup"]
    cfg = wg["Configuration"]
    assert cfg["EnforceWorkGroupConfiguration"] is True, (
        f"expected EnforceWorkGroupConfiguration=True from the CFN-deployed workgroup, got {cfg['EnforceWorkGroupConfiguration']!r}"
    )
    assert cfg["ResultConfiguration"]["OutputLocation"] == f"s3://{enforced_bucket}/", (
        f"expected the CFN-deployed workgroup's own output location s3://{enforced_bucket}/, "
        f"got {cfg['ResultConfiguration']['OutputLocation']!r}"
    )

    # Client asks for a DIFFERENT output location; workgroup enforcement must win.
    resp = athena.start_query_execution(
        QueryString="SELECT 1",
        WorkGroup=wg_name,
        ResultConfiguration={"OutputLocation": f"s3://{requested_bucket}/"},
    )
    qeid = resp["QueryExecutionId"]
    ctx.on_cleanup(lambda: athena.stop_query_execution(QueryExecutionId=qeid))

    qe = _poll_query_execution(ctx, qeid)
    actual_location = qe["ResultConfiguration"]["OutputLocation"]
    assert actual_location.startswith(f"s3://{enforced_bucket}/"), (
        f"expected enforced bucket location, got {actual_location}"
    )
    assert qe["Status"]["State"] == "SUCCEEDED", (
        f"expected query {qeid} to succeed, got state {qe['Status']['State']!r} "
        f"({qe['Status'].get('StateChangeReason')})"
    )

    # The actual result object landed in the enforced bucket, not the requested one.
    enforced_objs = s3.list_objects_v2(Bucket=enforced_bucket, Prefix=qeid)
    assert enforced_objs.get("KeyCount", 0) >= 1, (
        f"expected at least one result object under {qeid} in the enforced bucket "
        f"{enforced_bucket}, found {enforced_objs.get('KeyCount', 0)}"
    )
    requested_objs = s3.list_objects_v2(Bucket=requested_bucket)
    assert requested_objs.get("KeyCount", 0) == 0, (
        f"expected zero objects in the client-requested bucket {requested_bucket} "
        f"despite EnforceWorkGroupConfiguration=true, found {requested_objs.get('KeyCount', 0)}"
    )


def _create_bucket(ctx, tag: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-behav-athena-{tag}-").lower()
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 quirk: CreateBucket rejects an explicit LocationConstraint for its own region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]},
    )
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=bucket,
                Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
            )
    s3.delete_bucket(Bucket=bucket)


def _deploy_cfn(ctx, stack_name: str, template_body: str) -> None:
    cfn = ctx.client("cloudformation")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _poll_query_execution(ctx, query_execution_id: str, timeout_s: float = 60.0) -> dict:
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    qe = None
    while time.monotonic() < deadline:
        qe = athena.get_query_execution(QueryExecutionId=query_execution_id)["QueryExecution"]
        if qe["Status"]["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return qe
        time.sleep(1.5)
    raise AssertionError(f"query execution did not reach a terminal state in {timeout_s}s: {qe}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
