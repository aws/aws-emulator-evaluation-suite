"""sfn-distributed-map-without-start-execution-permission-fails-with-zero-children."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-distributed-map-without-start-execution-permission-fails-with-zero-children"
GROUP = 'overly_permissive'
SERVICES = ['s3', 'stepfunctions']

_ITEMS_KEY = "input/items.json"
_N_ITEMS = 6


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """A Distributed Map whose role cannot start its own children fails with zero child
    executions (ListExecutions for the map run is empty), and with the grant added it runs all six.
    """
    s3 = ctx.client("s3")
    sfn = ctx.client("stepfunctions")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _create_bucket(ctx)
    item_ids = [f"item-{i:02d}" for i in range(_N_ITEMS)]
    s3.put_object(
        Bucket=bucket,
        Key=_ITEMS_KEY,
        Body=json.dumps([{"itemId": i} for i in item_ids]).encode(),
    )

    # The role has every grant the map needs except states:StartExecution, which a Distributed
    # Map needs to launch its own children.
    role_name, role_arn, policy_name = _create_map_role_without_start_execution(
        ctx, bucket, account_id
    )

    definition = {
        "Comment": "a distributed map over six items, one trivial child each",
        "StartAt": "Fan",
        "States": {
            "Fan": {
                "Type": "Map",
                "MaxConcurrency": _N_ITEMS,
                "ItemReader": {
                    "Resource": "arn:aws:states:::s3:getObject",
                    "ReaderConfig": {"InputType": "JSON"},
                    "Parameters": {"Bucket": bucket, "Key": _ITEMS_KEY},
                },
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
                    "StartAt": "Echo",
                    "States": {
                        "Echo": {
                            "Type": "Pass",
                            "Parameters": {"itemId.$": "$.itemId"},
                            "End": True,
                        }
                    },
                },
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    # IAM propagation has no condition to poll, so run a bounded sequence of fresh executions
    # until one fails specifically on the missing grant.
    first = None
    for _ in range(8):
        first = _start_and_wait(ctx, sm_arn)
        if "not authorized to perform: states:StartExecution" in (first.get("cause") or ""):
            break
        time.sleep(5)
    assert first["status"] == "FAILED", (
        f'the unprivileged execution was {first["status"]!r}, expected FAILED: '
        f'{first.get("error")!r} {first.get("cause")!r}'
    )
    # AWS reports States.Runtime here, not States.Permissions; the name alone matches any runtime
    # fault, so the cause is asserted too.
    assert first["error"] == "States.Runtime", (
        f'the unprivileged execution failed with {first["error"]!r}, expected States.Runtime. '
        f'cause was {first.get("cause")!r}'
    )
    assert "not authorized to perform: states:StartExecution" in (first.get("cause") or ""), (
        f'the failure cause does not name the missing grant: {first.get("cause")!r}'
    )

    first_map_run = _one_map_run(ctx, first["executionArn"])
    first_counters = sfn.describe_map_run(mapRunArn=first_map_run)["itemCounts"]
    assert first_counters["succeeded"] == 0, (
        f"the map run recorded successes without permission to start any child: "
        f"{first_counters!r}"
    )
    children = _child_executions(ctx, sm_arn, first_map_run)
    assert children == [], (
        f"{len(children)!r} child executions ran despite the missing states:StartExecution "
        f"grant: {children!r}"
    )

    # Bounded fresh executions absorb IAM propagation. Right after the policy update AWS can
    # also fail one with States.ResultWriterFailed or a spurious AssumeRole denial, so any
    # FAILED execution is retried.
    _grant_start_execution(ctx, role_name, policy_name, bucket, account_id)
    second = None
    for _ in range(8):
        second = _start_and_wait(ctx, sm_arn)
        if second["status"] == "SUCCEEDED":
            break
        time.sleep(5)
    assert second["status"] == "SUCCEEDED", (
        f'the privileged execution was {second["status"]!r}: '
        f'{second.get("error")!r} {second.get("cause")!r}'
    )

    second_map_run = _one_map_run(ctx, second["executionArn"])
    second_counters = sfn.describe_map_run(mapRunArn=second_map_run)["itemCounts"]
    assert (second_counters["succeeded"], second_counters["failed"]) == (_N_ITEMS, 0), (
        f"the privileged map run counted {second_counters!r}, expected {_N_ITEMS!r} succeeded "
        f"and 0 failed"
    )
    second_children = _child_executions(ctx, sm_arn, second_map_run)
    assert len(second_children) == _N_ITEMS, (
        f"the privileged map run started {len(second_children)!r} child executions, expected "
        f'{_N_ITEMS!r}: {[c["name"] for c in second_children]!r}'
    )
    assert {c["status"] for c in second_children} == {"SUCCEEDED"}, (
        f'the child executions ended as {sorted({c["status"] for c in second_children})!r}, '
        f"expected all SUCCEEDED"
    )


# ===== helpers =====
_MANAGED_TAG_KEY = "sim2real:managed"
_TAG_PREFIX = "sim2real-behav"


def _resource_tags():
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _TAG_PREFIX}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _tags_lower():
    return [{"key": k, "value": v} for k, v in _resource_tags().items()]


def _s3_statements(bucket):
    return [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": f"arn:aws:s3:::{bucket}/*",
        },
        {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
    ]


def _execution_statements(account_id, region):
    return [{
        "Effect": "Allow",
        "Action": ["states:DescribeExecution", "states:StopExecution"],
        "Resource": f"arn:aws:states:{region}:{account_id}:execution:*:*",
    }]


def _create_map_role_without_start_execution(ctx, bucket, account_id):
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
        Description="sim2real-behav sfn distributed-map role, deliberately missing a grant",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    policy_name = f"{role_name}-policy"

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": _s3_statements(bucket) + _execution_statements(account_id, ctx.region),
        }),
    )
    return role_name, role_arn, policy_name


def _grant_start_execution(ctx, role_name, policy_name, bucket, account_id):
    ctx.client("iam").put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["states:StartExecution"],
                    "Resource": f"arn:aws:states:{ctx.region}:{account_id}:stateMachine:*",
                },
                *_s3_statements(bucket),
                *_execution_statements(account_id, ctx.region),
            ],
        }),
    )


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


def _start_and_wait(ctx, sm_arn, *, timeout_s=240.0):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-behav-exec-"),
        input="{}",
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(2)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError:
        # An execution has no delete API; a terminal one may refuse the stop, any other refusal fails.
        if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
            raise


def _one_map_run(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    runs, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.list_map_runs(**kwargs)
        runs.extend(resp["mapRuns"])
        token = resp.get("nextToken")
        if not token:
            break
    assert len(runs) == 1, f"expected exactly one map run for {exec_arn!r}, got {runs!r}"
    return runs[0]["mapRunArn"]


def _child_executions(ctx, sm_arn, map_run_arn):
    """The map run's child executions, across all ListExecutions pages."""
    sfn = ctx.client("stepfunctions")
    out, token = [], None
    while True:
        kwargs = {"mapRunArn": map_run_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.list_executions(**kwargs)
        out.extend(resp["executions"])
        token = resp.get("nextToken")
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
