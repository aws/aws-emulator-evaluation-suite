"""run-order-two-starts-only-after-run-order-one-finishes."""
from __future__ import annotations

import io
import json
import os
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "run-order-two-starts-only-after-run-order-one-finishes"
GROUP = "ordering"
SERVICES = ["codepipeline"]

_TERMINAL = ("Succeeded", "Failed", "Stopped", "Cancelled", "Superseded")
_SCENARIO = "codepipeline-run-order-sequencing"


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """runOrder within a stage is real sequencing: a runOrder=2 action starts only after the
    runOrder=1 action's lastUpdateTime, and a control stage with both at runOrder=1 runs both.
    Every deploy action's bytes are read back from S3 first.
    """
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")
    create_timeout_s = 240
    run_timeout_s = 300

    bucket = _artifact_bucket(ctx, s3)
    source_bytes = _zip({"payload.bin": os.urandom(4096)})
    s3.put_object(Bucket=bucket, Key="source.zip", Body=source_bytes)
    role_arn = _pipeline_role(ctx, bucket)

    seq_name = ctx.unique_name("sim2real-behav-cpseq-")
    par_name = ctx.unique_name("sim2real-behav-cppar-")

    # "Bravo" is declared FIRST in both stages, so declaration order disagrees with runOrder in
    # the sequential pipeline and an emulator that honours list position instead of runOrder is
    # caught as well. Alphabetical order also disagrees with the intended sequence.
    for name, bravo_run_order in ((seq_name, 2), (par_name, 1)):
        _create_with_role_propagation(
            cp, _pipeline(name, role_arn, bucket, bravo_run_order),
            timeout_s=create_timeout_s)
        ctx.on_cleanup(lambda n=name: cp.delete_pipeline(name=n))

    seq_exec = _first_execution(ctx, cp, seq_name, timeout_s=run_timeout_s)
    par_exec = _first_execution(ctx, cp, par_name, timeout_s=run_timeout_s)
    ctx.on_cleanup(lambda: _abandon(cp, seq_name, seq_exec))
    ctx.on_cleanup(lambda: _abandon(cp, par_name, par_exec))

    for name, exec_id in ((seq_name, seq_exec), (par_name, par_exec)):
        status = _poll(ctx, lambda n=name, e=exec_id: _execution_status(cp, n, e),
                       lambda s: s in _TERMINAL, timeout_s=run_timeout_s, interval_s=2,
                       what=f"execution {exec_id} of {name!r} to reach a terminal status")
        assert status == "Succeeded", (
            f"both pipelines must Succeed so that two complete action windows exist to compare; "
            f"execution {exec_id} of {name!r} expected 'Succeeded', got {status!r}. Record: "
            f"{_execution(cp, name, exec_id)!r}"
        )

    # The bytes actually moved, before any timing is examined.
    for name in (seq_name, par_name):
        for action in ("alpha", "bravo"):
            key = f"{name}/{action}.zip"
            body = _poll(ctx, lambda k=key: _get_object(s3, bucket, k), lambda b: b is not None,
                         timeout_s=run_timeout_s, interval_s=2,
                         what=f"the {action} Deploy action of {name!r} to write {key!r}")
            assert body == source_bytes, (
                f"the {action} action of {name!r} must deploy the source archive to {key!r}; "
                f"delivered {len(body)} bytes, expected {len(source_bytes)}"
            )

    seq_alpha, seq_bravo = _action_windows(cp, seq_name, seq_exec)
    _action_windows(cp, par_name, par_exec)

    assert seq_bravo["start"] >= seq_alpha["end"], (
        f"Bravo declares runOrder=2, so it must not start until Alpha (runOrder=1) has finished: "
        f"in {seq_name!r} Bravo started {seq_alpha['end'] - seq_bravo['start']:.3f}s BEFORE "
        f"Alpha's lastUpdateTime (Alpha {seq_alpha['start']:.3f}..{seq_alpha['end']:.3f}, Bravo "
        f"{seq_bravo['start']:.3f}..{seq_bravo['end']:.3f}, epoch seconds). An emulator that "
        f"dispatches every action in a stage at once, or in declaration order, fails here."
    )

    # The declaration must still say what this check assumed, so the comparison above cannot be
    # explained by the service having rewritten the runOrders.
    declared = _declared_run_orders(cp, seq_name)
    assert declared == {"Alpha": 1, "Bravo": 2}, (
        f"GetPipeline for {seq_name!r} must still report Alpha at runOrder 1 and Bravo at "
        f"runOrder 2; got {declared!r}"
    )
    declared_par = _declared_run_orders(cp, par_name)
    assert declared_par == {"Alpha": 1, "Bravo": 1}, (
        f"GetPipeline for the parallel control {par_name!r} must report both actions at runOrder "
        f"1; got {declared_par!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, fn, pred, *, timeout_s, interval_s, what):
    """Poll fn() until pred(value); raise on timeout, naming what it waited for."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(
                f"timed out after {timeout_s:.0f}s waiting for {what}; last observed value {val!r}"
            )
        time.sleep(interval_s)
        val = fn()
    return val


def _zip(entries) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry, body in entries.items():
            zf.writestr(entry, body)
    return buf.getvalue()


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _get_object(s3, bucket, key):
    """The object bytes, or None if the key does not exist yet."""
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in ("NoSuchKey", "404", "NotFound"):
            return None
        raise


def _purge_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", []))
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _artifact_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-behav-cporder-").lower()
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    return bucket


def _pipeline_role(ctx, bucket) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cporder-")
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "codepipeline.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="artifacts",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject",
                           "s3:GetBucketVersioning", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="artifacts"))
    return f"arn:aws:iam::{_account_id(ctx)}:role/{name}"


def _create_with_role_propagation(cp, declaration, *, timeout_s):
    """CreatePipeline, retried while it answers InvalidStructureException for a new role that
    is still propagating."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cp.create_pipeline(pipeline=declaration)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (err.get("Code") == "InvalidStructureException"
                         and "AssumeRole" in err.get("Message", ""))
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _deploy_action(action_name, bucket, object_key, run_order):
    return {
        "name": action_name,
        "actionTypeId": {"category": "Deploy", "owner": "AWS", "provider": "S3", "version": "1"},
        "runOrder": run_order,
        "configuration": {"BucketName": bucket, "Extract": "false", "ObjectKey": object_key},
        "inputArtifacts": [{"name": "SourceOutput"}],
    }


def _pipeline(name, role_arn, bucket, bravo_run_order):
    """Source(S3) -> one Deploy stage holding two S3 Deploy actions. Bravo is declared FIRST so
    declaration order and alphabetical order both disagree with the intended sequence."""
    return {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "pipelineType": "V2",
        "executionMode": "QUEUED",
        "stages": [
            {"name": "Source", "actions": [{
                "name": "Source",
                "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3",
                                 "version": "1"},
                "runOrder": 1,
                "configuration": {"S3Bucket": bucket, "S3ObjectKey": "source.zip",
                                  "PollForSourceChanges": "false"},
                "outputArtifacts": [{"name": "SourceOutput"}],
            }]},
            {"name": "Deploy", "actions": [
                _deploy_action("Bravo", bucket, f"{name}/bravo.zip", bravo_run_order),
                _deploy_action("Alpha", bucket, f"{name}/alpha.zip", 1),
            ]},
        ],
    }


def _execution(cp, name, execution_id):
    return cp.get_pipeline_execution(
        pipelineName=name, pipelineExecutionId=execution_id)["pipelineExecution"]


def _execution_status(cp, name, execution_id):
    try:
        return _execution(cp, name, execution_id)["status"]
    except ClientError:
        return None


def _execution_ids(cp, name):
    ids = []
    for page in cp.get_paginator("list_pipeline_executions").paginate(pipelineName=name):
        ids.extend(s["pipelineExecutionId"] for s in page.get("pipelineExecutionSummaries", []))
    return ids


def _first_execution(ctx, cp, name, *, timeout_s):
    ids = _poll(ctx, lambda: _execution_ids(cp, name), lambda i: len(i) >= 1,
                timeout_s=timeout_s, interval_s=2,
                what=f"CreatePipeline to auto-start an execution of {name!r}")
    return ids[0]


def _action_executions(cp, name, execution_id):
    out, token = [], None
    while True:
        kw = {"pipelineName": name, "filter": {"pipelineExecutionId": execution_id}}
        if token:
            kw["nextToken"] = token
        page = cp.list_action_executions(**kw)
        out.extend(page.get("actionExecutionDetails", []))
        token = page.get("nextToken")
        if not token:
            return out


def _action_windows(cp, name, execution_id):
    """The (start, end) epoch-second windows of the Alpha and Bravo Deploy actions, matched by
    actionName rather than list position."""
    details = _action_executions(cp, name, execution_id)
    by_name = {}
    for d in details:
        if d.get("stageName") != "Deploy":
            continue
        action = d.get("actionName")
        start, end = d.get("startTime"), d.get("lastUpdateTime")
        assert start is not None and end is not None, (
            f"ListActionExecutions must report startTime and lastUpdateTime for the {action!r} "
            f"action of {name!r}; got startTime {start!r}, lastUpdateTime {end!r} in {d!r}"
        )
        by_name[action] = {"start": start.timestamp(), "end": end.timestamp()}
    assert set(by_name) == {"Alpha", "Bravo"}, (
        f"expected exactly the Alpha and Bravo Deploy action records for execution "
        f"{execution_id} of {name!r}; got {sorted(by_name)!r} from "
        f"{[(d.get('stageName'), d.get('actionName')) for d in details]!r}"
    )
    return by_name["Alpha"], by_name["Bravo"]


def _declared_run_orders(cp, name):
    """The runOrder the service reports for each Deploy action, so the timing comparison cannot be
    explained by the declaration having been rewritten."""
    pipeline = cp.get_pipeline(name=name)["pipeline"]
    for stage in pipeline["stages"]:
        if stage["name"] == "Deploy":
            return {a["name"]: a["runOrder"] for a in stage["actions"]}
    raise AssertionError(
        f"GetPipeline for {name!r} must report a Deploy stage; stages were "
        f"{[s['name'] for s in pipeline['stages']]!r}"
    )


def _abandon(cp, name, execution_id):
    try:
        cp.stop_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id, abandon=True,
            reason="sim2real behavioral check teardown")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "PipelineNotFoundException":
            return
        # An execution that already finished cannot be stopped; its status confirms it.
        if code != "PipelineExecutionNotStoppableException" or _execution_status(
            cp, name, execution_id
        ) not in _TERMINAL:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
