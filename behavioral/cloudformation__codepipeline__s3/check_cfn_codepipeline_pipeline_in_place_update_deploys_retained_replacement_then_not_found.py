"""cfn-codepipeline-pipeline-in-place-update-deploys-retained-replacement-then-not-found."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-codepipeline-pipeline-in-place-update-deploys-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "codepipeline", "s3"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: An S3-to-S3 execution finishes within a few minutes; the bound only stops a hung poll.
_EXECUTION_S = 600.0
#: A role reaches CodePipeline within seconds; the bound only stops a retry loop.
_TRUST_S = 120.0
#: A change or delete reaches every read within seconds; the bound only stops a hung poll.
_PROPAGATE_S = 60.0
#: One deadline for the whole teardown, within the suites' 1800 s cleanup budget.
_TEARDOWN_CAP_S = 1500.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_IAM = ["CAPABILITY_IAM"]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
#: The role CodePipeline cannot assume yet; CreateStack is retried only on this reason.
_NOT_ASSUMABLE = "is not authorized to perform AssumeRole on role"
_RUNNING = ("InProgress", "Stopping")
#: StopPipelineExecution's refusal of an execution that has already ended.
_NOT_STOPPABLE = (
    "PipelineExecutionNotStoppableException",
    "The pipeline execution with ID '{execution_id}' in '{name}' can't be stopped now. "
    "Either it does not exist in the pipeline, or the pipeline execution has no action "
    "executions in progress.",
)
#: ListPipelineExecutions' refusal of a pipeline that does not exist.
_LIST_NOT_FOUND = (
    "PipelineNotFoundException",
    "The account with AWS account ID '{account}' does not include a pipeline named '{name}'",
)
#: S3's refusal of a bucket that does not exist.
_NO_BUCKET = ("NoSuchBucket", "The specified bucket does not exist")
_SOURCE_KEY = "source.zip"
_FILE = "hello.txt"
_CONTENT = b"reality check artifact\n"


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """An AWS::CodePipeline::Pipeline survives create, in-place update, retained replace and delete.

    GetPipeline reads back each template; after the deploy path changes in place an execution
    moves the S3 source to the new path, and a Name change under Retain keeps the old pipeline.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codepipeline-pipeline.html
    """
    cfn = ctx.client("cloudformation")
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-cfnreal-cp-").lower().replace("_", "-")
    stack_name = ctx.unique_name("sim2real-cfnreal-cp-")
    pipeline_v1 = ctx.unique_name("sim2real-cfnreal-cp-a-")
    pipeline_v2 = ctx.unique_name("sim2real-cfnreal-cp-b-")

    account = ctx.account
    # LIFO: running executions stop, the stack goes, then the retained pipeline, then the
    # bucket they write to. Teardown waits share one deadline of their own. DeletePipeline of
    # a name that does not exist succeeds.
    limit: dict = {}
    ctx.on_cleanup(lambda: _drop_bucket(s3, bucket))
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_v1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name, limit))
    ctx.on_cleanup(lambda: _stop_executions(cp, account, [pipeline_v1, pipeline_v2], limit))
    # us-east-1 is the one region whose CreateBucket takes no LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})
    # The S3 source action requires a versioned source bucket.
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    _put_versioned(ctx, s3, bucket, _SOURCE_KEY, _zip())

    # ---- 1. create: CloudFormation view, CodePipeline view ------------------------------------
    stack_id = _create_retrying_role(ctx, cfn, stack_name, _template(pipeline_v1, bucket, "site-a"))
    _assert_tracks(cfn, stack_id, "Pipeline", pipeline_v1)
    outputs = _outputs(cfn, stack_id)
    role_arn = outputs["RoleArn"]
    assert outputs["Version"] == "1", f"GetAtt Pipeline.Version of a new pipeline: {outputs!r}"
    _assert_pipeline(ctx, cp, pipeline_v1, role_arn, bucket, "site-a", 1)
    # Behaviour: CreatePipeline starts the first execution itself, which deploys to site-a/.
    _await_first_execution(ctx, cp, pipeline_v1)
    deployed = s3.get_object(Bucket=bucket, Key=f"site-a/{_FILE}")["Body"].read()
    assert deployed == _CONTENT, (
        f"the first execution must extract {_FILE} under site-a/: {deployed!r}"
    )

    # ---- 2. in place: the deploy path changes, then an execution deploys there ---------------
    body = _template(pipeline_v1, bucket, "site-b")
    rows = _update(ctx, cfn, stack_id, "Pipeline", body, Capabilities=_IAM)
    _assert_updated_in_place(rows, pipeline_v1)
    assert _outputs(cfn, stack_id)["Version"] == "2", "an update raises GetAtt Pipeline.Version"
    _assert_pipeline(ctx, cp, pipeline_v1, role_arn, bucket, "site-b", 2)

    execution_id = cp.start_pipeline_execution(name=pipeline_v1)["pipelineExecutionId"]
    execution = _poll(
        ctx,
        lambda: _execution(cp, pipeline_v1, execution_id),
        lambda e: e is not None and e["status"] not in _RUNNING,
        cap_s=_EXECUTION_S,
        interval_s=3.0,
        what=f"execution {execution_id} of {pipeline_v1} to finish",
    )
    assert (execution["status"], execution["pipelineVersion"]) == ("Succeeded", 2), (
        f"the execution must run version 2 to success, got {execution!r}"
    )
    state = cp.get_pipeline_state(name=pipeline_v1)
    stages = [
        (
            s["stageName"],
            s.get("latestExecution", {}).get("pipelineExecutionId"),
            s.get("latestExecution", {}).get("status"),
        )
        for s in state["stageStates"]
    ]
    assert stages == [
        ("Source", execution_id, "Succeeded"),
        ("Deploy", execution_id, "Succeeded"),
    ], f"GetPipelineState must show both stages of {execution_id} succeeded, got {stages!r}"
    assert state["pipelineVersion"] == 2, f"GetPipelineState pipelineVersion: {state!r}"
    deployed = s3.get_object(Bucket=bucket, Key=f"site-b/{_FILE}")["Body"].read()
    assert deployed == _CONTENT, (
        f"the Deploy stage must extract {_FILE} under site-b/: {deployed!r}"
    )

    # ---- 3. Name forces replacement; UpdateReplacePolicy Retain keeps the old pipeline -------
    body = _template(pipeline_v2, bucket, "site-b")
    rows = _update(ctx, cfn, stack_id, "Pipeline", body, Capabilities=_IAM)
    _assert_replaced_and_retained(rows, pipeline_v1, pipeline_v2)
    _assert_tracks(cfn, stack_id, "Pipeline", pipeline_v2)
    _assert_pipeline(ctx, cp, pipeline_v2, role_arn, bucket, "site-b", 1)
    _await_first_execution(ctx, cp, pipeline_v2)
    _assert_pipeline(ctx, cp, pipeline_v1, role_arn, bucket, "site-b", 2)

    # ---- 4. DeleteStack: the pipeline it owns is gone, the retained one stays ----------------
    _delete_and_confirm(ctx, cfn, stack_id)
    want = (
        "PipelineNotFoundException",
        f"Account '{ctx.account}' does not have a pipeline with name '{pipeline_v2}'",
    )
    _await_error(ctx, lambda: cp.get_pipeline(name=pipeline_v2), want, "GetPipeline after delete")
    assert cp.get_pipeline(name=pipeline_v1)["pipeline"]["version"] == 2, "the retained one stays"


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(_FILE, _CONTENT)
    return buf.getvalue()


def _stages(bucket: str, deploy_path: str) -> list[dict]:
    return [
        {
            "Name": "Source",
            "Actions": [
                {
                    "Name": "Fetch",
                    "ActionTypeId": {
                        "Category": "Source",
                        "Owner": "AWS",
                        "Provider": "S3",
                        "Version": "1",
                    },
                    "Configuration": {
                        "S3Bucket": bucket,
                        "S3ObjectKey": _SOURCE_KEY,
                        "PollForSourceChanges": "false",
                    },
                    "OutputArtifacts": [{"Name": "Src"}],
                    "RunOrder": 1,
                }
            ],
        },
        {
            "Name": "Deploy",
            "Actions": [
                {
                    "Name": "Publish",
                    "ActionTypeId": {
                        "Category": "Deploy",
                        "Owner": "AWS",
                        "Provider": "S3",
                        "Version": "1",
                    },
                    # With Extract true, ObjectKey is the path the files are extracted under.
                    "Configuration": {
                        "BucketName": bucket,
                        "Extract": "true",
                        "ObjectKey": deploy_path,
                    },
                    "InputArtifacts": [{"Name": "Src"}],
                    "RunOrder": 1,
                }
            ],
        },
    ]


def _template(name: str, bucket: str, deploy_path: str) -> str:
    bucket_arn = {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket}"}
    objects_arn = {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket}/*"}
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "PipelineRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "codepipeline.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "bucket",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "s3:GetObject",
                                                "s3:GetObjectVersion",
                                                "s3:PutObject",
                                                "s3:GetBucketVersioning",
                                                "s3:GetBucketAcl",
                                                "s3:GetBucketLocation",
                                                "s3:ListBucket",
                                            ],
                                            "Resource": [bucket_arn, objects_arn],
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "Pipeline": {
                    "Type": "AWS::CodePipeline::Pipeline",
                    # Name is create-only, so a new name replaces the pipeline.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "Name": name,
                        "PipelineType": "V2",
                        "RoleArn": {"Fn::GetAtt": ["PipelineRole", "Arn"]},
                        "ArtifactStore": {"Type": "S3", "Location": bucket},
                        "Stages": _stages(bucket, deploy_path),
                    },
                },
            },
            "Outputs": {
                "RoleArn": {"Value": {"Fn::GetAtt": ["PipelineRole", "Arn"]}},
                "Version": {"Value": {"Fn::GetAtt": ["Pipeline", "Version"]}},
            },
        }
    )


def _assert_pipeline(
    ctx, cp, name: str, role_arn: str, bucket: str, deploy_path: str, version: int
) -> None:
    """CodePipeline's view: GetPipeline carries exactly the template's declaration."""
    declared = _poll(
        ctx,
        lambda: cp.get_pipeline(name=name)["pipeline"],
        lambda p: p["version"] == version,
        cap_s=_PROPAGATE_S,
        what=f"GetPipeline on {name} to read version {version}",
    )
    got = {
        "name": declared["name"],
        "roleArn": declared["roleArn"],
        "artifactStore": declared["artifactStore"],
        "pipelineType": declared.get("pipelineType"),
        "stages": [
            (
                stage["name"],
                [
                    (
                        a["name"],
                        a["actionTypeId"],
                        a.get("configuration"),
                        [i["name"] for i in a.get("inputArtifacts", [])],
                        [o["name"] for o in a.get("outputArtifacts", [])],
                    )
                    for a in stage["actions"]
                ],
            )
            for stage in declared["stages"]
        ],
    }
    want = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "pipelineType": "V2",
        "stages": [
            (
                stage["Name"],
                [
                    (
                        a["Name"],
                        {k[0].lower() + k[1:]: v for k, v in a["ActionTypeId"].items()},
                        a["Configuration"],
                        [i["Name"] for i in a.get("InputArtifacts", [])],
                        [o["Name"] for o in a.get("OutputArtifacts", [])],
                    )
                    for a in stage["Actions"]
                ],
            )
            for stage in _stages(bucket, deploy_path)
        ],
    }
    assert got == want, f"GetPipeline must read back the template: {got!r}, want {want!r}"


def _outputs(cfn, stack_id: str) -> dict:
    return {o["OutputKey"]: o.get("OutputValue") for o in _stack(cfn, stack_id).get("Outputs", [])}


def _create_retrying_role(ctx, cfn, stack_name: str, body: str) -> str:
    """CreateStack until CREATE_COMPLETE and return the StackId.

    A fresh role can reach CodePipeline only seconds after IAM returns it, and no read shows
    when; a rollback for exactly that reason is deleted and created again, within _TRUST_S.
    """
    deadline = time.monotonic() + _budget_s(ctx, _TRUST_S)
    while True:
        stack_id = cfn.create_stack(
            StackName=stack_name, Capabilities=_IAM, Tags=_TAGS, TemplateBody=body
        )["StackId"]
        created = _settle(ctx, cfn, stack_id)
        if created["StackStatus"] == "CREATE_COMPLETE":
            return stack_id
        reasons = [
            e.get("ResourceStatusReason") or ""
            for e in _events(cfn, stack_id)
            if e["LogicalResourceId"] == "Pipeline" and e["ResourceStatus"] == "CREATE_FAILED"
        ]
        retry = (
            created["StackStatus"] == "ROLLBACK_COMPLETE"
            and len(reasons) == 1
            and _NOT_ASSUMABLE in reasons[0]
            and time.monotonic() < deadline
        )
        assert retry, (
            f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}; "
            f"Pipeline failures {reasons!r}"
        )
        _delete_and_confirm(ctx, cfn, stack_id)
        time.sleep(5.0)


def _put_versioned(ctx, s3, bucket: str, key: str, body: bytes) -> str:
    """PutObject until S3 versions the write; enabled versioning reaches writes within seconds.

    A write that got no version id is the null version, which is deleted before the next try.
    """

    def attempt():
        version = s3.put_object(Bucket=bucket, Key=key, Body=body).get("VersionId")
        if version in (None, "null"):
            s3.delete_object(Bucket=bucket, Key=key, VersionId="null")
            return None
        return version

    return _poll(
        ctx,
        attempt,
        lambda version: version is not None,
        cap_s=_PROPAGATE_S,
        what=f"a PutObject to the versioning-enabled {bucket} to get a version id",
    )


def _empty_bucket(s3, bucket: str) -> None:
    """Delete every object version and delete marker; a bucket already gone is fine."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
    except ClientError as exc:
        if _error(exc) != _NO_BUCKET:
            raise


def _drop_bucket(s3, bucket: str) -> None:
    _empty_bucket(s3, bucket)
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if _error(exc) != _NO_BUCKET:
            raise


def _error(exc: ClientError) -> tuple:
    err = exc.response.get("Error", {})
    return err.get("Code"), err.get("Message")


def _execution(cp, name: str, execution_id: str) -> dict | None:
    """GetPipelineExecution, or None while a just-started execution is not yet readable.

    CodePipeline answers PipelineExecutionNotFoundException for the id StartPipelineExecution
    returned until the execution reaches its reads.
    """
    try:
        return cp.get_pipeline_execution(pipelineName=name, pipelineExecutionId=execution_id)[
            "pipelineExecution"
        ]
    except ClientError as exc:
        err = exc.response["Error"]
        lag = (
            "PipelineExecutionNotFoundException",
            f"Pipeline Execution with id '{execution_id}' does not exist in pipeline with name "
            f"'{name}'",
        )
        if (err.get("Code"), err.get("Message")) != lag:
            raise
        return None


def _await_first_execution(ctx, cp, name: str) -> None:
    """The one execution CreatePipeline started runs version 1 to success."""
    summaries = _poll(
        ctx,
        lambda: cp.list_pipeline_executions(pipelineName=name)["pipelineExecutionSummaries"],
        lambda runs: len(runs) == 1 and runs[0]["status"] not in _RUNNING,
        cap_s=_EXECUTION_S,
        interval_s=3.0,
        what=f"the execution CreatePipeline started on {name} to finish",
    )
    first = summaries[0]
    got = {"status": first["status"], "triggerType": first.get("trigger", {}).get("triggerType")}
    assert got == {"status": "Succeeded", "triggerType": "CreatePipeline"}, (
        f"the execution CreatePipeline started on {name} must succeed, got {first!r}"
    )
    execution = cp.get_pipeline_execution(
        pipelineName=name, pipelineExecutionId=first["pipelineExecutionId"]
    )["pipelineExecution"]
    assert execution["pipelineVersion"] == 1, f"the first execution runs version 1: {execution!r}"


def _stop_executions(cp, account: str, names: list[str], limit: dict) -> None:
    """Teardown: abandon every running execution, so none writes after the bucket is emptied."""
    for name in names:
        try:
            runs = cp.list_pipeline_executions(pipelineName=name)["pipelineExecutionSummaries"]
            for run in runs:
                if run["status"] == "InProgress":
                    _abandon(cp, name, run["pipelineExecutionId"])
            _poll(
                None,
                lambda n=name: cp.list_pipeline_executions(pipelineName=n)[
                    "pipelineExecutionSummaries"
                ],
                lambda rs: all(r["status"] not in _RUNNING for r in rs),
                cap_s=_remaining(limit),
                interval_s=3.0,
                what=f"executions of {name} to stop",
            )
        except ClientError as exc:
            gone = (_LIST_NOT_FOUND[0], _LIST_NOT_FOUND[1].format(account=account, name=name))
            if _error(exc) != gone:
                raise


def _abandon(cp, name: str, execution_id: str) -> None:
    """Stop an execution without waiting for its actions; one that just finished is fine."""
    try:
        cp.stop_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id, abandon=True, reason="teardown"
        )
    except ClientError as exc:
        err = exc.response["Error"]
        expected = _NOT_STOPPABLE[1].format(execution_id=execution_id, name=name)
        if (err["Code"], err.get("Message")) != (_NOT_STOPPABLE[0], expected):
            raise


def _await_error(ctx, fn, want: tuple[str, str], what: str) -> None:
    """Poll fn until it is refused, then assert the exact (code, message) want.

    A delete reaches every read within seconds, so a call that still succeeds is retried.
    """
    timeout_s = _budget_s(ctx, _PROPAGATE_S)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            got = (err.get("Code"), err.get("Message") or "")
            assert got == want, f"{what}: {got!r}, expected {want!r}"
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while {what} still succeeded; not graded")
            raise AssertionError(f"{what} still succeeded after {timeout_s:.0f}s: {result!r}")
        time.sleep(2.0)


# ===== stack helpers =====


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    Teardown passes ctx=None and keeps the fixed cap: the runner's deadline does not cover it.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 2.0):
    """Call probe() until done(result) holds and return it; ctx=None (teardown) is not budgeted."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(ctx, cfn, stack_id: str) -> dict:
    """The stack once no operation (cleanup phase included) is in progress on it."""
    return _poll(
        ctx,
        lambda: _stack(cfn, stack_id),
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled",
    )


def _physical(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _assert_tracks(cfn, stack_id: str, logical_id: str, expected: str) -> None:
    """CloudFormation's view: the stack resource carries the expected PhysicalResourceId."""
    got = _physical(cfn, stack_id, logical_id)
    assert got == expected, f"the stack must track {logical_id} as {expected!r}, got {got!r}"


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _update(ctx, cfn, stack_id: str, logical_id: str, body: str, **kw) -> list[tuple]:
    """UpdateStack to body, assert UPDATE_COMPLETE and return the update's rows for logical_id.

    A row is (ResourceStatus, ResourceStatusReason, PhysicalResourceId), oldest first.
    """
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=body, **kw)
    stack = _settle(ctx, cfn, stack_id)
    events = _events(cfn, stack_id)[before:]
    failed = [
        (e["LogicalResourceId"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"update ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}; {failed!r}"
    )
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """Whether every wanted row occurs in rows in that order; a None field matches any value."""
    remaining = iter(rows)
    return all(
        any(all(w is None or w == v for w, v in zip(want, row, strict=True)) for row in remaining)
        for want in wanted
    )


def _assert_updated_in_place(rows: list[tuple], physical: str) -> None:
    """The update completed on the same physical id and reported no replacement or delete."""
    assert _in_order(
        rows, [("UPDATE_IN_PROGRESS", None, None), ("UPDATE_COMPLETE", None, physical)]
    ), f"an in-place update must progress and complete on {physical!r}: {rows!r}"
    replacing = [r for r in rows if r[1] == _REPLACING or r[0].startswith("DELETE_")]
    assert replacing == [], f"an in-place update must not replace anything: {replacing!r}"


def _assert_replaced_and_retained(rows: list[tuple], old: str, new: str) -> None:
    """The update reported a replacement, completed on the new id and skipped deleting the old."""
    assert _in_order(
        rows,
        [
            ("UPDATE_IN_PROGRESS", _REPLACING, None),
            ("UPDATE_COMPLETE", None, new),
            ("DELETE_SKIPPED", None, old),
        ],
    ), (
        f"the replacement must report creating a new resource, complete as {new!r} and skip "
        f"deleting {old!r} (UpdateReplacePolicy Retain), in that order: {rows!r}"
    )
    deleted = [r for r in rows if r[0] in ("DELETE_IN_PROGRESS", "DELETE_COMPLETE")]
    assert deleted == [], f"UpdateReplacePolicy Retain must delete nothing: {deleted!r}"


def _delete_and_confirm(ctx, cfn, stack_id: str) -> None:
    """DeleteStack by StackId and assert it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        ctx,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    assert final == "DELETE_COMPLETE", (
        f"DeleteStack ended {final!r}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
    )


def _remaining(limit: dict) -> float:
    """Seconds left of the one teardown deadline, which starts at the first teardown wait."""
    deadline = limit.setdefault("at", time.monotonic() + _TEARDOWN_CAP_S)
    return max(1.0, deadline - time.monotonic())


def _delete_stack(cfn, stack_name: str, limit: dict) -> None:
    """Teardown: delete the stack by its StackId and wait; DELETE_FAILED or a timeout raises."""
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    status = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_remaining(limit),
        what=f"stack {stack_id} settled before teardown",
    )
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
        cap_s=_remaining(limit),
        what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
