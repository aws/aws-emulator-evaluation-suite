"""create-sync-job-unassumable-role-rejected."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-sync-job-unassumable-role-rejected"
GROUP = "overly-permissive"
SERVICES = ["iottwinmaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSyncJob with a syncRole that iottwinmaker.amazonaws.com cannot assume fails ValidationException with
    the exact message and no sync job exists, while a properly trusted role on the same workspace is accepted."""
    tm = ctx.client("iottwinmaker")
    iam = ctx.client("iam")
    workspace_id, _workspace_role_arn, _bucket = _create_workspace(ctx)

    sync_source = "SITEWISE"

    untrusted_role_name = ctx.unique_name("sim2real-tm-untrusted-role-")
    untrusted_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    untrusted_role_arn = iam.create_role(
        RoleName=untrusted_role_name,
        AssumeRolePolicyDocument=untrusted_trust,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, untrusted_role_name))

    refusal = _poll_for_stable_error(
        lambda: tm.create_sync_job(workspaceId=workspace_id, syncSource=sync_source, syncRole=untrusted_role_arn)
    )
    assert refusal["Code"] == "ValidationException", f"unexpected error={refusal!r}"
    expected = "Could not assume the role provided, verify permissions"
    assert refusal["Message"] == expected, f"expected message {expected!r}, got {refusal!r}"

    # effect absent: no SyncJob was created for this workspace/syncSource pair (the rejected
    # CreateSyncJob call never got far enough to persist a job record).
    not_found = _client_error(lambda: tm.get_sync_job(syncSource=sync_source, workspaceId=workspace_id))
    assert not_found["Code"] == "ResourceNotFoundException", f"unexpected error={not_found!r}"
    expected = "Provided Sync Job does not exist!"
    assert not_found["Message"] == expected, f"expected message {expected!r}, got {not_found!r}"

    # positive control: the same syncSource, this time with a role iottwinmaker can assume -- the
    # call itself is accepted (it is not rejected the way the untrusted role was), regardless of
    # how the sync ultimately resolves once it starts reading from IoT SiteWise.
    trusted_role_name = ctx.unique_name("sim2real-tm-trusted-role-")
    trusted_role_arn = iam.create_role(
        RoleName=trusted_role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, trusted_role_name))
    iam.put_role_policy(
        RoleName=trusted_role_name,
        PolicyName="sitewise-read",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["iotsitewise:List*", "iotsitewise:Describe*"], "Resource": "*"}],
            }
        ),
    )

    create_resp = _retry_create_sync_job(ctx, workspace_id, sync_source, trusted_role_arn)
    ctx.on_cleanup(lambda: _delete_sync_job(tm, workspace_id, sync_source))
    assert create_resp["state"] in ("CREATING", "INITIALIZING", "ACTIVE", "ERROR"), create_resp

    # terminal read is independent of the mutating CreateSyncJob call: GetSyncJob is a different
    # operation, issued at the destination, and proves the job the create call reported now exists
    # for real rather than only in that call's own echoed response.
    get_resp = tm.get_sync_job(workspaceId=workspace_id, syncSource=sync_source)
    assert get_resp["status"]["state"] in ("CREATING", "INITIALIZING", "ACTIVE", "ERROR"), get_resp


_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "iottwinmaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _s3_policy_document(bucket_name):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetBucket*", "s3:GetObject", "s3:ListBucket", "s3:PutObject", "s3:DeleteObject"],
                    "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
                }
            ],
        }
    )


def _delete_bucket(ctx, bucket_name):
    s3 = ctx.client("s3")
    try:
        for obj in s3.list_objects_v2(Bucket=bucket_name).get("Contents", []):
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_workspace_role(ctx):
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-tm-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket_name))
    role_name = ctx.unique_name("sim2real-tm-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="s3access", PolicyDocument=_s3_policy_document(bucket_name))
    return role_arn, bucket_name


def _create_workspace(ctx):
    tm = ctx.client("iottwinmaker")
    role_arn, bucket_name = _create_workspace_role(ctx)
    workspace_id = ctx.unique_name("sim2real-tm-ws-")
    deadline = time.monotonic() + 60
    last_exc = None
    while time.monotonic() < deadline:
        try:
            tm.create_workspace(
                workspaceId=workspace_id,
                s3Location=f"arn:aws:s3:::{bucket_name}",
                role=role_arn,
                tags={"sim2real-check": CHECK},
            )
            break
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = exc
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"CreateWorkspace never succeeded (IAM propagation?): {last_exc}")
    ctx.on_cleanup(lambda: _delete_workspace(tm, workspace_id))
    return workspace_id, role_arn, bucket_name


# budget.cleanup_timeout for behavioral/iottwinmaker, one deadline shared by the teardowns.
_TEARDOWN_RETRY_S = 900.0
_TEARDOWN_DEADLINES: dict = {}


def _teardown_left(tm) -> float:
    held = _TEARDOWN_DEADLINES.get(id(tm))
    if held is None or held[0] is not tm:
        held = _TEARDOWN_DEADLINES[id(tm)] = (tm, time.monotonic() + _TEARDOWN_RETRY_S)
    return held[1] - time.monotonic()


def _delete_sync_job(tm, workspace_id, sync_source):
    """Delete the sync job once its status allows it, then wait until it is gone, so the
    workspace delete after it is not refused. A missing job is done."""
    try:
        while True:
            try:
                tm.delete_sync_job(workspaceId=workspace_id, syncSource=sync_source)
                break
            except ClientError as exc:
                err = exc.response["Error"]
                # A job still CREATING/INITIALIZING refuses to transit to DELETING.
                not_yet = err["Code"] == "ValidationException" and err.get("Message", "").startswith(
                    "Cannot update syncJob status"
                )
                if not not_yet or _teardown_left(tm) <= 0:
                    raise
            time.sleep(2)
        while _teardown_left(tm) > 0:
            tm.get_sync_job(workspaceId=workspace_id, syncSource=sync_source)
            time.sleep(2)
        raise AssertionError(f"sync job {sync_source} of {workspace_id} still present at the cleanup deadline")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_workspace(tm, workspace_id):
    """Delete the workspace; retry the refusal while its sync job is still deleting."""
    while True:
        try:
            tm.delete_workspace(workspaceId=workspace_id)
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ResourceNotFoundException":
                return
            busy = (err["Code"], err.get("Message")) == (
                "ValidationException", "Workspace has syncJobs. Delete all resources in the workspace."
            )
            if not busy or _teardown_left(tm) <= 0:
                raise
        time.sleep(2)


def _client_error(fn):
    """The error a refused call returns; a call that succeeds raises."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_for_stable_error(fn, timeout_s=45.0):
    """IAM role visibility/trust evaluation can lag right after CreateRole; poll until the call
    settles on a non-transient error."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _client_error(fn)
        if last["Code"] == "ValidationException":
            return last
        time.sleep(3)
    return last


def _retry_create_sync_job(ctx, workspace_id, sync_source, role_arn, timeout_s=45.0):
    tm = ctx.client("iottwinmaker")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return tm.create_sync_job(workspaceId=workspace_id, syncSource=sync_source, syncRole=role_arn)
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"CreateSyncJob never succeeded with a trusted role: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
