"""glue-workflow-runs-its-second-trigger-only-after-the-first-job-succeeds."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "glue-workflow-runs-its-second-trigger-only-after-the-first-job-succeeds"
GROUP = 'workflows'
SERVICES = ['glue', 's3']

_PRODUCER = b"""import sys
import boto3

args = {}
for i, a in enumerate(sys.argv):
    if a.startswith('--') and i + 1 < len(sys.argv):
        args[a[2:]] = sys.argv[i + 1]
bucket, key = args['OUT'][len('s3://'):].split('/', 1)
boto3.client('s3').put_object(
    Bucket=bucket, Key=key, Body=str(int(args['SEED']) * 3).encode())
"""

# The consumer cannot produce its answer without reading the producer's object, so its
# output existing at all is proof the producer ran to completion first.
_CONSUMER = b"""import sys
import boto3

args = {}
for i, a in enumerate(sys.argv):
    if a.startswith('--') and i + 1 < len(sys.argv):
        args[a[2:]] = sys.argv[i + 1]
s3 = boto3.client('s3')
in_bucket, in_key = args['IN'][len('s3://'):].split('/', 1)
upstream = int(s3.get_object(Bucket=in_bucket, Key=in_key)['Body'].read().strip())
out_bucket, out_key = args['OUT'][len('s3://'):].split('/', 1)
s3.put_object(Bucket=out_bucket, Key=out_key, Body=str(upstream + 7).encode())
"""


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """A CONDITIONAL trigger starts the consumer job only after the producer job SUCCEEDED.

    Proven causally (the consumer writes seed*3+7 derived from the producer's object) and by
    the graph's JobRun timestamps (consumer StartedOn >= producer CompletedOn).
    """
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    seed = 3 + int(time.time()) % 90
    producer_key = "wf/produced.txt"
    consumer_key = "wf/consumed.txt"
    warmup_key = "wf/warmup.txt"

    bucket = ctx.unique_name("sim2real-behav-gluewf-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real",
                                                             "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="scripts/producer.py", Body=_PRODUCER)
    s3.put_object(Bucket=bucket, Key="scripts/consumer.py", Body=_CONSUMER)

    role_arn = _create_glue_role(ctx, iam, bucket, write=True)

    producer = ctx.unique_name("sim2real-behav-gluewfprod-")
    glue.create_job(
        Name=producer, Role=role_arn,
        Command={"Name": "pythonshell", "PythonVersion": "3.9",
                 "ScriptLocation": f"s3://{bucket}/scripts/producer.py"},
        MaxCapacity=0.0625, GlueVersion="3.0",
        ExecutionProperty={"MaxConcurrentRuns": 5},
        DefaultArguments={"--SEED": str(seed), "--OUT": f"s3://{bucket}/{producer_key}"},
        Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_job(JobName=producer),
                                         f"glue job {producer}"))

    consumer = ctx.unique_name("sim2real-behav-gluewfcons-")
    glue.create_job(
        Name=consumer, Role=role_arn,
        Command={"Name": "pythonshell", "PythonVersion": "3.9",
                 "ScriptLocation": f"s3://{bucket}/scripts/consumer.py"},
        MaxCapacity=0.0625, GlueVersion="3.0",
        ExecutionProperty={"MaxConcurrentRuns": 5},
        DefaultArguments={"--IN": f"s3://{bucket}/{producer_key}",
                          "--OUT": f"s3://{bucket}/{consumer_key}"},
        Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_job(JobName=consumer),
                                         f"glue job {consumer}"))

    # Standalone producer run first: it warms the new role (the workflow engine cannot retry a
    # run FAILED on an unpropagated role) and proves the producer works on its own.
    warmup = _run_job_to_terminal(glue, producer,
                                 {"--SEED": str(seed),
                                  "--OUT": f"s3://{bucket}/{warmup_key}"})
    assert warmup["JobRunState"] == "SUCCEEDED", (
        f"the standalone producer control ended {warmup['JobRunState']!r}: "
        f"{warmup.get('ErrorMessage')!r}"
    )

    workflow = ctx.unique_name("sim2real-behav-gluewf-")
    glue.create_workflow(Name=workflow, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_workflow(Name=workflow),
                                         f"glue workflow {workflow}"))

    entry_trigger = ctx.unique_name("sim2real-behav-gluewfentry-")
    glue.create_trigger(Name=entry_trigger, WorkflowName=workflow, Type="ON_DEMAND",
                        Actions=[{"JobName": producer}], Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_trigger(Name=entry_trigger),
                                         f"glue trigger {entry_trigger}"))

    gate_trigger = ctx.unique_name("sim2real-behav-gluewfgate-")
    glue.create_trigger(Name=gate_trigger, WorkflowName=workflow, Type="CONDITIONAL",
                        StartOnCreation=True,
                        Predicate={"Logical": "ANY", "Conditions": [
                            {"LogicalOperator": "EQUALS", "JobName": producer,
                             "State": "SUCCEEDED"}]},
                        Actions=[{"JobName": consumer}], Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_trigger(Name=gate_trigger),
                                         f"glue trigger {gate_trigger}"))

    workflow_run = _workflow_to_terminal(glue, workflow)

    assert workflow_run["Status"] == "COMPLETED", (
        f"workflow run ended {workflow_run['Status']!r}, statistics "
        f"{workflow_run.get('Statistics')!r}"
    )
    statistics = workflow_run.get("Statistics", {})
    assert statistics.get("SucceededActions") == 2, (
        f"workflow statistics were {statistics!r}, expected 2 succeeded actions"
    )

    nodes = workflow_run.get("Graph", {}).get("Nodes", [])
    job_nodes = {n["Name"]: n for n in nodes if n.get("Type") == "JOB"}
    assert set(job_nodes) == {producer, consumer}, (
        f"the workflow graph's JOB nodes were {sorted(job_nodes)!r}, expected the producer "
        f"and the consumer"
    )
    states = {name: [r["JobRunState"] for r in node["JobDetails"]["JobRuns"]]
              for name, node in job_nodes.items()}
    assert states == {producer: ["SUCCEEDED"], consumer: ["SUCCEEDED"]}, (
        f"job run states inside the workflow were {states!r}"
    )

    produced = _get_object(s3, bucket, producer_key)
    consumed = _get_object(s3, bucket, consumer_key)
    assert produced is not None and produced.strip() == str(seed * 3).encode(), (
        f"the producer wrote {produced!r}, expected {str(seed * 3).encode()!r}"
    )
    assert consumed is not None and consumed.strip() == str(seed * 3 + 7).encode(), (
        f"the consumer wrote {consumed!r}, expected {str(seed * 3 + 7).encode()!r} -- a "
        f"value it can only compute by reading the producer's object"
    )

    producer_completed = job_nodes[producer]["JobDetails"]["JobRuns"][0]["CompletedOn"]
    consumer_started = job_nodes[consumer]["JobDetails"]["JobRuns"][0]["StartedOn"]
    assert consumer_started >= producer_completed, (
        f"the consumer started at {consumer_started!r}, before the producer completed at "
        f"{producer_completed!r}, so the conditional trigger did not gate it"
    )


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _create_glue_role(ctx, iam, bucket: str, *, write: bool) -> str:
    """Create a role Glue can assume, with read (and optionally write) on one bucket."""
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Principal": {"Service": "glue.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]})
    role = ctx.unique_name("sim2real-behav-gluerole-")
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: iam.delete_role(RoleName=role),
                                         f"iam role {role}"))
    managed = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role, PolicyArn=managed)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.detach_role_policy(RoleName=role, PolicyArn=managed),
        f"detach {managed} from {role}"))
    actions = ["s3:GetObject", "s3:PutObject"] if write else ["s3:GetObject"]
    iam.put_role_policy(RoleName=role, PolicyName="sim2real-s3", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions,
                       "Resource": f"arn:aws:s3:::{bucket}/*"},
                      {"Effect": "Allow", "Action": ["s3:ListBucket"],
                       "Resource": f"arn:aws:s3:::{bucket}"}]}))
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.delete_role_policy(RoleName=role, PolicyName="sim2real-s3"),
        f"inline policy on {role}"))
    return arn


def _run_job_to_terminal(glue, job: str, arguments: dict, *, timeout_s: float = 600.0) -> dict:
    """Start the job and poll to a terminal state, retrying the IAM-propagation failure.

    Glue reports "Role ... should be given assume role permissions for Glue Service" as a
    FAILED job *run* about 5s in, not as a StartJobRun error, and no API reports that the
    role has become assumable -- so the bounded retry has to be on the terminal run state.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    record: dict = {}
    while time.monotonic() < deadline:
        try:
            run_id = glue.start_job_run(JobName=job, Arguments=arguments)["JobRunId"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConcurrentRunsExceededException":
                raise
            time.sleep(5)
            continue
        while time.monotonic() < deadline:
            record = glue.get_job_run(JobName=job, RunId=run_id)["JobRun"]
            if record["JobRunState"] in ("SUCCEEDED", "FAILED", "STOPPED", "ERROR",
                                         "TIMEOUT"):
                break
            time.sleep(5)
        if record.get("JobRunState") != "FAILED":
            return record
        if "assume role permissions" not in (record.get("ErrorMessage") or ""):
            return record
        time.sleep(2)
    return record


def _get_object(s3, bucket: str, key: str):
    from botocore.exceptions import ClientError
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchKey":
            return None
        raise


def _list_keys(s3, bucket: str, prefix: str) -> list:
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _retry_delete(fn: Callable[[], Any], label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry over throttling and dependency conflicts; raise on failure."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "NoSuchEntity", "NoSuchBucket",
            "ResourceNotFoundException", "404")
    transient = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                 "OperationTimeoutException", "ConcurrentModificationException",
                 "DeleteConflict", "InvalidInputException", "RequestLimitExceeded")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in gone:
                return
            if code not in transient or time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: {code}: {err}") from err
            time.sleep(3)
        except Exception as exc:  # noqa: BLE001 - re-raised
            raise RuntimeError(f"{label}: {type(exc).__name__}: {exc}") from exc


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    from botocore.exceptions import ClientError

    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                       for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise
        return
    _retry_delete(lambda: s3.delete_bucket(Bucket=bucket), f"s3 bucket {bucket}")


def _workflow_to_terminal(glue, workflow: str, *, timeout_s: float = 900.0) -> dict:
    run_id = glue.start_workflow_run(Name=workflow)["RunId"]
    deadline = time.monotonic() + timeout_s
    status = None
    record: dict = {}
    while time.monotonic() < deadline:
        record = glue.get_workflow_run(Name=workflow, RunId=run_id,
                                      IncludeGraph=True)["Run"]
        status = record.get("Status")
        if status in ("COMPLETED", "STOPPED", "ERROR"):
            return record
        time.sleep(5)
    raise AssertionError(
        f"workflow run {run_id!r} did not reach a terminal status within {timeout_s}s "
        f"(last status {status!r}, statistics {record.get('Statistics')!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
