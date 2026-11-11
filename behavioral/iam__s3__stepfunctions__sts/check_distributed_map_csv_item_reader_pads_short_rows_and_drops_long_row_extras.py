"""distributed-map-csv-item-reader-pads-short-rows-and-drops-long-row-extras."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "distributed-map-csv-item-reader-pads-short-rows-and-drops-long-row-extras"
GROUP = "distributed_map"
SERVICES = ["iam", "s3", "stepfunctions", "sts"]

_HEADERS = ["sku", "color", "qty"]
# short: fewer fields than the header; exact: a well-formed control row; long: more fields.
_CSV = "sku,color,qty\nA-1,red\nB-2,blue,12\nC-3,green,7,extra,extra2\n"
_EXPECTED = [
    {"sku": "A-1", "color": "red", "qty": ""},
    {"sku": "B-2", "color": "blue", "qty": "12"},
    {"sku": "C-3", "color": "green", "qty": "7"},
]


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """A Distributed Map CSV ItemReader fills a short row's missing trailing columns with
    empty strings and drops a long row's columns past the header, keyed by the header names.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/input-output-itemreader.html
    """
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    s3.put_object(Bucket=bucket, Key="rows.csv", Body=_CSV.encode())
    role_arn = _create_role(ctx, bucket)
    sm_arn = _create_state_machine(ctx, role_arn, bucket)

    desc = _run_to_terminal(ctx, sm_arn)
    assert desc["status"] == "SUCCEEDED", (
        f'execution was {desc["status"]!r}: {desc.get("error")!r} {desc.get("cause")!r}'
    )

    got = json.loads(desc["output"])
    assert sorted(got, key=lambda r: r["sku"]) == sorted(_EXPECTED, key=lambda r: r["sku"]), (
        f"the children were handed {got!r}; the file's rows keyed by {_HEADERS!r} are "
        f"{_EXPECTED!r}"
    )
    for row in got:
        assert set(row) == set(_HEADERS), (
            f"row {row!r} must carry exactly the header keys {_HEADERS!r}, never an extra column"
        )


# ===== helpers =====

def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}]


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-dmapcsv-")
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv()})
    return bucket


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_role(ctx, bucket):
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-dmapcsvrole-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn distributed-map csv execution role", Tags=_tags_kv(),
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    statements = [
        {"Effect": "Allow", "Action": ["states:StartExecution"],
         "Resource": f"arn:aws:states:{ctx.region}:{account_id}:stateMachine:*"},
        {"Effect": "Allow", "Action": ["states:DescribeExecution", "states:StopExecution"],
         "Resource": f"arn:aws:states:{ctx.region}:{account_id}:execution:*:*"},
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
    ]
    iam.put_role_policy(
        RoleName=role_name, PolicyName=f"{role_name}-policy",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return role_arn


def _create_state_machine(ctx, role_arn, bucket):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-dmapcsv-")
    definition = {
        "StartAt": "Items",
        "States": {
            "Items": {
                "Type": "Map",
                "ItemReader": {
                    "Resource": "arn:aws:states:::s3:getObject",
                    "ReaderConfig": {"InputType": "CSV", "CSVHeaderLocation": "FIRST_ROW"},
                    "Parameters": {"Bucket": bucket, "Key": "rows.csv"},
                },
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
                    "StartAt": "Identity",
                    "States": {"Identity": {"Type": "Pass", "End": True}},
                },
                "End": True,
            },
        },
    }
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                type="STANDARD", tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


_PROPAGATION_MARKERS = (
    "not authorized to assume", "cannot be assumed", "sts:AssumeRole",
    "States.Permissions", "AccessDenied",
)


def _run_to_terminal(ctx, sm_arn, *, timeout_s=200.0, propagation_s=120.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + propagation_s
    while True:
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _stop_execution_cleanup(ctx, a))
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return desc
        if time.monotonic() >= deadline:
            return desc
        time.sleep(2)


def _wait_terminal(ctx, exec_arn, *, timeout_s, interval_s=2.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _stop_execution_cleanup(ctx, exec_arn):
    """StopExecution on an already-terminal execution still answers 200 (idempotent)."""
    ctx.client("stepfunctions").stop_execution(
        executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
