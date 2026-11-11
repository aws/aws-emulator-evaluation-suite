"""sfn-distributed-map-over-real-s3-objects-writes-a-result-manifest."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-distributed-map-over-real-s3-objects-writes-a-result-manifest"
GROUP = 'distributed_map'
SERVICES = ['s3', 'stepfunctions']

_N_OBJECTS = 12
_INPUT_PREFIX = "input/"
_OUTPUT_PREFIX = "output"
_MANAGED_TAG_KEY = "sim2real:managed"
_TAG_PREFIX = "sim2real-behav"


def _resource_tags():
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _TAG_PREFIX}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _tags_lower():
    return [{"key": k, "value": v} for k, v in _resource_tags().items()]


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """A Distributed Map iterating a real S3 listing of 12 objects runs 12 child executions and
    its ResultWriter writes a manifest whose result files hold each child's own output.
    """
    s3 = ctx.client("s3")
    sfn = ctx.client("stepfunctions")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _create_bucket(ctx)
    expected = {}
    for i in range(_N_OBJECTS):
        key = f"{_INPUT_PREFIX}item-{i:04d}.json"
        s3.put_object(Bucket=bucket, Key=key, Body=json.dumps({"n": i}).encode())
        expected[key] = i * 2

    role_arn = _create_distributed_map_role(ctx, bucket, account_id)

    definition = {
        "Comment": "distributed map over a real S3 listing, results written back to S3",
        "StartAt": "Fan",
        "States": {
            "Fan": {
                "Type": "Map",
                "MaxConcurrency": _N_OBJECTS,
                "ItemReader": {
                    "Resource": "arn:aws:states:::s3:listObjectsV2",
                    "Parameters": {"Bucket": bucket, "Prefix": _INPUT_PREFIX},
                },
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
                    "StartAt": "Read",
                    "States": {
                        "Read": {
                            "Type": "Task",
                            "Resource": "arn:aws:states:::aws-sdk:s3:getObject",
                            "Parameters": {"Bucket": bucket, "Key.$": "$.Key"},
                            "ResultSelector": {"body.$": "$.Body"},
                            "ResultPath": "$.fetched",
                            "Next": "Parse",
                        },
                        "Parse": {
                            "Type": "Pass",
                            "Parameters": {
                                "key.$": "$.Key",
                                "obj.$": "States.StringToJson($.fetched.body)",
                            },
                            "Next": "Emit",
                        },
                        "Emit": {
                            "Type": "Pass",
                            "Parameters": {
                                "key.$": "$.key",
                                "doubled.$": "States.MathAdd($.obj.n, $.obj.n)",
                            },
                            "End": True,
                        },
                    },
                },
                "ResultWriter": {
                    "Resource": "arn:aws:states:::s3:putObject",
                    "Parameters": {"Bucket": bucket, "Prefix": _OUTPUT_PREFIX},
                },
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    exe = _run_to_terminal(ctx, sm_arn, {}, timeout_s=240.0)
    assert exe["status"] == "SUCCEEDED", (
        f'execution was {exe["status"]!r}: {exe.get("error")!r} {exe.get("cause")!r}'
    )

    map_runs = _map_runs(ctx, exe["executionArn"])
    assert len(map_runs) == 1, f"expected one map run, ListMapRuns returned {map_runs!r}"
    counters = sfn.describe_map_run(mapRunArn=map_runs[0]["mapRunArn"])["itemCounts"]
    assert (counters["succeeded"], counters["failed"]) == (_N_OBJECTS, 0), (
        f"the map run counted {counters!r}, expected {_N_OBJECTS!r} succeeded and 0 failed"
    )

    # The manifest location comes from the field that holds it, never from splitting a URI.
    writer = json.loads(exe["output"])["ResultWriterDetails"]
    assert writer["Bucket"] == bucket, (
        f"the ResultWriter wrote to {writer!r}, expected bucket {bucket!r}"
    )
    manifest = json.loads(
        s3.get_object(Bucket=writer["Bucket"], Key=writer["Key"])["Body"].read()
    )
    succeeded_files = manifest["ResultFiles"]["SUCCEEDED"]
    assert succeeded_files and all(f["Size"] > 0 for f in succeeded_files), (
        f'the manifest ResultFiles were {manifest["ResultFiles"]!r}'
    )
    assert manifest["ResultFiles"]["FAILED"] == [], (
        f'the manifest reports failed result files: {manifest["ResultFiles"]["FAILED"]!r}'
    )

    per_key_output = {}
    for f in succeeded_files:
        for record in json.loads(
            s3.get_object(Bucket=writer["Bucket"], Key=f["Key"])["Body"].read()
        ):
            child_output = json.loads(record["Output"])
            per_key_output[child_output["key"]] = child_output["doubled"]
    assert set(per_key_output) == set(expected), (
        f"the results cover {sorted(per_key_output)!r}, the inputs were {sorted(expected)!r}"
    )
    assert per_key_output == expected, (
        f"each child must return the transform of its OWN object's body; the children "
        f"produced {per_key_output!r}, expected {expected!r}"
    )

    listed = _list_keys(ctx, bucket, _OUTPUT_PREFIX)
    assert {f["Key"] for f in succeeded_files} <= listed, (
        f"the manifest names result files that are not in the bucket: "
        f'{sorted({f["Key"] for f in succeeded_files} - listed)!r}'
    )


# ===== helpers =====
def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-sfnmap-")
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv()})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _list_keys(ctx, bucket, prefix):
    s3 = ctx.client("s3")
    out = set()
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        out.update(o["Key"] for o in page.get("Contents", []))
    return out


def _create_distributed_map_role(ctx, bucket, account_id, *, extra=()):
    """The role a Distributed Map needs: start its own children, and read/write the bucket."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn distributed-map execution role",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    policy_name = f"{role_name}-policy"

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    statements = [
        {
            "Effect": "Allow",
            "Action": ["states:StartExecution"],
            "Resource": f"arn:aws:states:{ctx.region}:{account_id}:stateMachine:*",
        },
        {
            "Effect": "Allow",
            "Action": ["states:DescribeExecution", "states:StopExecution"],
            "Resource": f"arn:aws:states:{ctx.region}:{account_id}:execution:*:*",
        },
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": f"arn:aws:s3:::{bucket}/*",
        },
        {
            "Effect": "Allow",
            "Action": ["s3:ListBucket"],
            "Resource": f"arn:aws:s3:::{bucket}",
        },
        *extra,
    ]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation has no condition to poll; the bounded retries in _create_state_machine and
    # _run_to_terminal absorb it.
    return role_arn


def _create_state_machine(ctx, definition, role_arn, *, sm_type="STANDARD",
                          name_prefix="sim2real-behav-sm-"):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name(name_prefix)
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type,
                tags=_tags_lower(),
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
    "States.Permissions",
    "AccessDenied",
)


def _run_to_terminal(ctx, sm_arn, input_payload, *, timeout_s=240.0, max_attempts=6):
    """Start an execution and poll to terminal, retrying with fresh executions (bounded).

    An unpropagated inline policy fails the map run almost instantly when it starts children.
    """
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(max_attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn,
            name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(input_payload),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(5)
    return desc


def _wait_terminal(ctx, exec_arn, *, timeout_s=240.0, interval_s=2.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError:
        # An execution has no delete API; a terminal one may refuse the stop, any other refusal fails.
        if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
            raise


def _map_runs(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    out, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.list_map_runs(**kwargs)
        out.extend(resp["mapRuns"])
        token = resp.get("nextToken")
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
