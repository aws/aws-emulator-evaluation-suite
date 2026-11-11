"""deploy-workgroup-cloudformation-enforces-configuration."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-workgroup-cloudformation-enforces-configuration"
GROUP = "deploy"
SERVICES = ["athena"]

_WG_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  WorkGroupName:
    Type: String
  OutputLocation:
    Type: String
Resources:
  WG:
    Type: AWS::Athena::WorkGroup
    Properties:
      Name: !Ref WorkGroupName
      RecursiveDeleteOption: true
      WorkGroupConfiguration:
        ResultConfiguration:
          OutputLocation: !Ref OutputLocation
        EnforceWorkGroupConfiguration: true
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A WorkGroup deployed via AWS::Athena::WorkGroup with EnforceWorkGroupConfiguration
    actually forces StartQueryExecution to use its configured S3 output location, even
    when the caller omits ResultConfiguration entirely -- not merely CREATE_COMPLETE."""
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    athena = ctx.client("athena")

    bucket = ctx.unique_name("sim2real-athena-cfn-wg-")
    _create_bucket(ctx, s3, bucket)
    output_location = f"s3://{bucket}/athena-results/"

    stack_name = ctx.unique_name("sim2real-athena-wg-stack-")
    wg_name = ctx.unique_name("sim2real-athena-wg-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_WG_TEMPLATE,
        Parameters=[
            {"ParameterKey": "WorkGroupName", "ParameterValue": wg_name},
            {"ParameterKey": "OutputLocation", "ParameterValue": output_location},
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    def _delete_stack():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )

    ctx.on_cleanup(_delete_stack)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    wg = athena.get_work_group(WorkGroup=wg_name)["WorkGroup"]
    cfg = wg["Configuration"]
    assert cfg["ResultConfiguration"]["OutputLocation"] == output_location, (
        f"expected stack-configured output location {output_location!r}, got "
        f"{cfg['ResultConfiguration']['OutputLocation']!r}"
    )
    assert cfg["EnforceWorkGroupConfiguration"] is True, (
        f"expected EnforceWorkGroupConfiguration=True, got {cfg['EnforceWorkGroupConfiguration']!r}"
    )

    # StartQueryExecution intentionally omits ResultConfiguration -- if the workgroup
    # truly enforces its configuration, Athena must supply the output location itself.
    qid = athena.start_query_execution(QueryString="SELECT 1", WorkGroup=wg_name)[
        "QueryExecutionId"
    ]
    ctx.on_cleanup(lambda: _stop_query(athena, qid))

    def _terminal():
        qe = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = qe["Status"]["State"]
        return qe if state in ("SUCCEEDED", "FAILED", "CANCELLED") else None

    qe = _poll_until(_terminal, timeout_s=90, interval_s=2)
    assert qe["Status"]["State"] == "SUCCEEDED", (
        f"expected SUCCEEDED, got {qe['Status']['State']!r}: "
        f"{qe['Status'].get('StateChangeReason')}"
    )
    result_location = qe["ResultConfiguration"]["OutputLocation"]
    assert result_location.startswith(output_location), (
        f"expected result location under enforced {output_location!r}, got {result_location!r}"
    )


def _create_bucket(ctx, s3, bucket: str) -> None:
    region = ctx.region
    # us-east-1 rejects an explicit CreateBucketConfiguration; every other region requires one.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})


def _stop_query(athena, qid: str) -> None:
    """Teardown: stop the query; a stop of a finished query is a no-op, and only Athena's
    unknown-query answer (InvalidRequestException) is tolerated."""
    from botocore.exceptions import ClientError

    try:
        athena.stop_query_execution(QueryExecutionId=qid)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidRequestException":
            raise


def _poll_until(probe, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = probe()
        if result is not None:
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
