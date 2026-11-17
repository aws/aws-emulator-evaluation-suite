"""cfn-glue-security-configuration-replacement-updates-the-job-it-encrypts-in-place."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-glue-security-configuration-replacement-updates-the-job-it-encrypts-in-place"
GROUP = "deploy"
SERVICES = ["cloudformation", "glue", "kms", "logs", "s3"]

#: A stack create/update/delete takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: A Python shell run at 0.0625 DPU starts and finishes within a couple of minutes.
_RUN_S = 300.0
#: CloudWatch Logs' own view of a just-created or just-updated log group lags briefly.
_PROPAGATE_S = 90.0
#: One deadline for the whole teardown, within the suites' 1800 s cleanup budget.
_TEARDOWN_CAP_S = 1500.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_IAM = ["CAPABILITY_IAM"]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
_SCRIPT_KEY = "scripts/noop.py"
#: The job performs no I/O; its own response and the log group it writes to carry the assertion.
_SCRIPT = b"import sys\n\nsys.exit(0)\n"
_NO_JOB = ("EntityNotFoundException", "Job not found.")
_NO_SEC_CONFIG = ("EntityNotFoundException", "")
_TERMINAL = ("SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR", "EXPIRED")


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
    """A deployed AWS::Glue::SecurityConfiguration encrypts the CloudWatch log group of the job
    referencing it; replacing it with a new Name and key updates the job in place to the new
    one, and the retained original keeps its own encryption after both the replacement and delete.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-securityconfiguration.html
    Reference: https://docs.aws.amazon.com/glue/latest/dg/encryption-security-configuration.html
    """
    cfn = ctx.client("cloudformation")
    glue = ctx.client("glue")
    kms = ctx.client("kms")
    logs = ctx.client("logs")
    s3 = ctx.client("s3")

    key_a = _create_cmk(ctx, kms, "a")
    key_b = _create_cmk(ctx, kms, "b")

    bucket = ctx.unique_name("sim2real-cfnreal-gsc-").lower().replace("_", "-")
    stack_name = ctx.unique_name("sim2real-cfnreal-gsc-")
    sc_v1 = ctx.unique_name("sim2real-cfnreal-gsc-a-")
    sc_v2 = ctx.unique_name("sim2real-cfnreal-gsc-b-")
    job_name = ctx.unique_name("sim2real-cfnreal-gsc-job-")
    runs: list[str] = []
    orphan: dict = {}

    limit: dict = {}
    ctx.on_cleanup(lambda: _drop_bucket(s3, bucket))
    ctx.on_cleanup(lambda: _delete_orphan(glue, orphan))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name, limit))
    ctx.on_cleanup(lambda: _stop_runs(glue, job_name, runs, limit))

    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})
    s3.put_object(Bucket=bucket, Key=_SCRIPT_KEY, Body=_SCRIPT)

    # ---- 1. create: a job referencing the security configuration writes an encrypted log group --
    stack_id = cfn.create_stack(
        StackName=stack_name,
        Capabilities=_IAM,
        Tags=_TAGS,
        TemplateBody=_template(sc_v1, job_name, bucket, key_a),
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    orphan["name"] = None
    _assert_tracks(cfn, stack_id, "SecConfig", sc_v1)
    _assert_tracks(cfn, stack_id, "Job", job_name)
    role_arn = _outputs(cfn, stack_id)["RoleArn"]
    _grant_role_key_use(kms, key_a, role_arn)
    _grant_role_key_use(kms, key_b, role_arn)
    _assert_security_configuration(glue, sc_v1, key_a)
    _assert_job(glue, job_name, role_arn, bucket, sc_v1)

    log_group_1 = _run_and_read_log_group(ctx, glue, logs, job_name, runs, key_a)

    # ---- 2. CloudFormation ships no update handler for this type: a new Name and KMS key -------
    # replace the security configuration, retaining the old one, and the job (whose
    # SecurityConfiguration property is not create-only) updates IN PLACE to follow it.
    before = len(_events(cfn, stack_id))
    cfn.update_stack(
        StackName=stack_id, TemplateBody=_template(sc_v2, job_name, bucket, key_b), Capabilities=_IAM
    )
    updated = _settle(ctx, cfn, stack_id)
    events = _events(cfn, stack_id)[before:]
    assert updated["StackStatus"] == "UPDATE_COMPLETE", (
        f"update ended {updated['StackStatus']!r}: {updated.get('StackStatusReason')!r}"
    )
    _assert_tracks(cfn, stack_id, "SecConfig", sc_v2)
    orphan["name"] = sc_v1
    _assert_replaced_and_retained(_rows_for(events, "SecConfig"), sc_v1, sc_v2)
    _assert_updated_in_place(_rows_for(events, "Job"), job_name)
    _assert_tracks(cfn, stack_id, "Job", job_name)

    _assert_security_configuration(glue, sc_v2, key_b)
    job = glue.get_job(JobName=job_name)["Job"]
    assert job["SecurityConfiguration"] == sc_v2, (
        f"the job must update in place to the replaced security configuration's name, "
        f"got {job['SecurityConfiguration']!r}"
    )
    # the retained original is untouched by the replacement that produced sc_v2
    _assert_security_configuration(glue, sc_v1, key_a)

    log_group_2 = _run_and_read_log_group(ctx, glue, logs, job_name, runs, key_b)
    assert log_group_2 != log_group_1, (
        f"a replaced security configuration must change the job's log group path, "
        f"still {log_group_2!r}"
    )

    # ---- 3. DeleteStack: the live security configuration is gone, the retained one survives -----
    _delete_and_confirm(ctx, cfn, stack_id)
    _await_error(ctx, lambda: glue.get_job(JobName=job_name), _NO_JOB, "GetJob after DeleteStack")
    _await_error(
        ctx,
        lambda: glue.get_security_configuration(Name=sc_v2),
        _NO_SEC_CONFIG,
        "GetSecurityConfiguration after DeleteStack",
    )
    assert _security_configuration(glue, sc_v1)["Name"] == sc_v1, (
        "the retained security configuration must survive DeleteStack"
    )


def _command(bucket: str) -> dict:
    return {
        "Name": "pythonshell",
        "ScriptLocation": f"s3://{bucket}/{_SCRIPT_KEY}",
        "PythonVersion": "3.9",
    }


def _template(sec_config_name: str, job_name: str, bucket: str, kms_key: dict) -> str:
    objects_arn = f"arn:${{AWS::Partition}}:s3:::{bucket}/*"
    logs_arn = "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:*"
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "JobRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "glue.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            {
                                "Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/"
                                "service-role/AWSGlueServiceRole"
                            }
                        ],
                        "Policies": [
                            {
                                "PolicyName": "jobaccess",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": ["s3:GetObject"],
                                            "Resource": {"Fn::Sub": objects_arn},
                                        },
                                        {
                                            "Effect": "Allow",
                                            "Action": ["logs:AssociateKmsKey"],
                                            "Resource": {"Fn::Sub": logs_arn},
                                        },
                                    ],
                                },
                            }
                        ],
                    },
                },
                "SecConfig": {
                    "Type": "AWS::Glue::SecurityConfiguration",
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "Name": sec_config_name,
                        "EncryptionConfiguration": {
                            "CloudWatchEncryption": {
                                "CloudWatchEncryptionMode": "SSE-KMS",
                                "KmsKeyArn": kms_key["arn"],
                            }
                        },
                    },
                },
                "Job": {
                    "Type": "AWS::Glue::Job",
                    "Properties": {
                        "Name": job_name,
                        "Role": {"Fn::GetAtt": ["JobRole", "Arn"]},
                        "GlueVersion": "3.0",
                        "Command": _command(bucket),
                        "MaxCapacity": 0.0625,
                        "MaxRetries": 0,
                        "Timeout": 5,
                        "SecurityConfiguration": {"Ref": "SecConfig"},
                    },
                },
            },
            "Outputs": {"RoleArn": {"Value": {"Fn::GetAtt": ["JobRole", "Arn"]}}},
        }
    )


def _security_configuration(glue, name: str) -> dict:
    return glue.get_security_configuration(Name=name)["SecurityConfiguration"]


def _assert_security_configuration(glue, name: str, kms_key: dict) -> None:
    """Glue's view: GetSecurityConfiguration reads back the exact CloudWatch encryption settings."""
    cfg = _security_configuration(glue, name)
    want = {"CloudWatchEncryptionMode": "SSE-KMS", "KmsKeyArn": kms_key["arn"]}
    got = cfg["EncryptionConfiguration"].get("CloudWatchEncryption")
    assert got == want, f"GetSecurityConfiguration({name!r}) CloudWatchEncryption: {got!r}, want {want!r}"


def _assert_job(glue, name: str, role_arn: str, bucket: str, sec_config_name: str) -> None:
    job = glue.get_job(JobName=name)["Job"]
    got = {
        k: job.get(k) for k in ("Name", "Role", "Command", "MaxCapacity", "SecurityConfiguration")
    }
    want = {
        "Name": name,
        "Role": role_arn,
        "Command": _command(bucket),
        "MaxCapacity": 0.0625,
        "SecurityConfiguration": sec_config_name,
    }
    assert got == want, f"GetJob must read back the template: {got!r}, want {want!r}"


def _start_job_run(ctx, glue, job_name: str) -> str:
    """StartJobRun, retrying ConcurrentRunsExceededException while the prior run's own completed
    state has not yet propagated to the job's active-run accounting."""
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while True:
        try:
            return glue.start_job_run(JobName=job_name)["JobRunId"]
        except ClientError as exc:
            if _error(exc)[0] != "ConcurrentRunsExceededException" or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


def _run_and_read_log_group(ctx, glue, logs, job_name: str, runs: list[str], kms_key: dict) -> str:
    """Start a run, wait for it to succeed, and return the log group CloudWatch encrypted with
    ``kms_key`` — proof that the deployed security configuration is actually in effect."""
    run_id = _start_job_run(ctx, glue, job_name)
    runs.append(run_id)
    job_run = _poll(
        ctx,
        lambda: glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"],
        lambda r: r["JobRunState"] in _TERMINAL,
        cap_s=_RUN_S,
        interval_s=5.0,
        what=f"run {run_id} of {job_name} to finish",
    )
    assert job_run["JobRunState"] == "SUCCEEDED", (
        f"the run must succeed, got {job_run['JobRunState']!r}: {job_run.get('ErrorMessage')!r}"
    )
    log_group_name = job_run["LogGroupName"]
    assert log_group_name != "/aws-glue/jobs/", (
        "a run of a job with a security configuration must not use the unencrypted default "
        f"log group, got {log_group_name!r}"
    )

    def _groups() -> list[dict]:
        return logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]

    matched = _poll(
        ctx,
        _groups,
        lambda groups: any(g.get("kmsKeyId") == kms_key["arn"] for g in groups),
        cap_s=_PROPAGATE_S,
        what=f"log group(s) under {log_group_name!r} to carry kmsKeyId {kms_key['arn']!r}",
    )
    found = [g["kmsKeyId"] for g in matched if g["logGroupName"].startswith(log_group_name)]
    assert kms_key["arn"] in found, (
        f"no log group under {log_group_name!r} carries kmsKeyId {kms_key['arn']!r}: {found!r}"
    )
    return log_group_name


def _create_cmk(ctx, kms, suffix: str) -> dict:
    key = kms.create_key(
        Description=f"sim2real glue security configuration cloudwatch key {suffix}",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7))
    _grant_logs_key_use(kms, key["KeyId"], ctx.region)
    return {"id": key["KeyId"], "arn": key["Arn"]}


def _grant_logs_key_use(kms, key_id: str, region: str) -> None:
    """CloudWatch Logs must be able to use the key to encrypt the log group it creates."""
    policy = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    policy["Statement"].append(
        {
            "Sid": "AllowCloudWatchLogsToUseTheKey",
            "Effect": "Allow",
            "Principal": {"Service": f"logs.{region}.amazonaws.com"},
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:Describe*",
            ],
            "Resource": "*",
        }
    )
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(policy))


def _grant_role_key_use(kms, kms_key: dict, role_arn: str) -> None:
    """The job's own role must also be able to use the key, per the AWS Glue encryption guide."""
    policy = json.loads(kms.get_key_policy(KeyId=kms_key["id"], PolicyName="default")["Policy"])
    policy["Statement"].append(
        {
            "Sid": "AllowTheGlueJobRoleToUseTheKey",
            "Effect": "Allow",
            "Principal": {"AWS": role_arn},
            "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"],
            "Resource": "*",
        }
    )
    kms.put_key_policy(KeyId=kms_key["id"], PolicyName="default", Policy=json.dumps(policy))


def _outputs(cfn, stack_id: str) -> dict:
    return {o["OutputKey"]: o.get("OutputValue") for o in _stack(cfn, stack_id).get("Outputs", [])}


def _error(exc: ClientError) -> tuple:
    err = exc.response.get("Error", {})
    return err.get("Code"), err.get("Message")


def _run_state(glue, job: str, run_id: str) -> str:
    return glue.get_job_run(JobName=job, RunId=run_id)["JobRun"]["JobRunState"]


def _stop_runs(glue, job: str, runs: list[str], limit: dict) -> None:
    """Teardown: stop a run that has not finished, so it writes nothing after the role is gone."""
    try:
        live = [r for r in runs if _run_state(glue, job, r) not in _TERMINAL]
    except ClientError as exc:
        if _error(exc) == _NO_JOB:
            return
        raise
    if not live:
        return
    failed = glue.batch_stop_job_run(JobName=job, JobRunIds=live).get("Errors")
    if failed:
        raise AssertionError(f"BatchStopJobRun refused {failed!r}")
    _poll(
        None,
        lambda: [_run_state(glue, job, r) for r in live],
        lambda states: all(s in _TERMINAL for s in states),
        cap_s=_remaining(limit),
        what=f"runs {live!r} of {job} to stop",
    )


def _delete_orphan(glue, orphan: dict) -> None:
    """Teardown: delete the security configuration the replacement step retained, if it ran."""
    name = orphan.get("name")
    if not name:
        return
    try:
        glue.delete_security_configuration(Name=name)
    except ClientError as exc:
        if _error(exc)[0] != "EntityNotFoundException":
            raise


def _empty_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
    except ClientError as exc:
        if _error(exc) != ("NoSuchBucket", "The specified bucket does not exist"):
            raise


def _drop_bucket(s3, bucket: str) -> None:
    _empty_bucket(s3, bucket)
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if _error(exc) != ("NoSuchBucket", "The specified bucket does not exist"):
            raise


def _await_error(ctx, fn, want: tuple[str, str], what: str) -> None:
    timeout_s = _budget_s(ctx, _PROPAGATE_S)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            got = _error(exc)
            assert got == want, f"{what}: {got!r}, expected {want!r}"
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while {what} still succeeded; not graded")
            raise AssertionError(f"{what} still succeeded after {timeout_s:.0f}s: {result!r}")
        time.sleep(2.0)


def _budget_s(ctx, cap_s: float) -> float:
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 2.0):
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
    got = _physical(cfn, stack_id, logical_id)
    assert got == expected, f"the stack must track {logical_id} as {expected!r}, got {got!r}"


def _events(cfn, stack_id: str) -> list[dict]:
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _rows_for(events: list[dict], logical_id: str) -> list[tuple]:
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    remaining = iter(rows)
    return all(
        any(all(w is None or w == v for w, v in zip(want, row, strict=True)) for row in remaining)
        for want in wanted
    )


def _assert_updated_in_place(rows: list[tuple], physical: str) -> None:
    assert _in_order(
        rows, [("UPDATE_IN_PROGRESS", None, None), ("UPDATE_COMPLETE", None, physical)]
    ), f"an in-place update must progress and complete on {physical!r}: {rows!r}"
    replacing = [r for r in rows if r[1] == _REPLACING or r[0].startswith("DELETE_")]
    assert replacing == [], f"an in-place update must not replace anything: {replacing!r}"


def _assert_replaced_and_retained(rows: list[tuple], old: str, new: str) -> None:
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
    deadline = limit.setdefault("at", time.monotonic() + _TEARDOWN_CAP_S)
    return max(1.0, deadline - time.monotonic())


def _delete_stack(cfn, stack_name: str, limit: dict) -> None:
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
