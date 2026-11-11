"""user-import-job-state-transitions."""
from __future__ import annotations

import json
import time
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "user-import-job-state-transitions"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A started user import job leaves Pending and ends Stopped, Failed or Succeeded (one imported
    user), and ListUserImportJobs lists it with the same final status as DescribeUserImportJob."""
    idp = ctx.client("cognito-idp")
    iam = ctx.client("iam")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:check": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_import_log_groups(ctx, pool_id))
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    role_name = ctx.unique_name("sim2real-cog-import-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cognito-idp.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="logs",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                            "logs:DescribeLogStreams",
                        ],
                        "Resource": "arn:aws:logs:*:*:*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _safe_delete_role_policy(iam, role_name, "logs"))

    job_name = ctx.unique_name("sim2real-import-")
    job = _retry_create_import_job(idp, pool_id, job_name, role_arn)
    job_id = job["JobId"]
    # A freshly created (not yet started) import job's initial status is
    # "Created" on real Cognito; it only becomes "Pending"/"InProgress" once
    # StartUserImportJob is called below.
    assert job["Status"] == "Created", f"expected a freshly created import job to be Created, got {job['Status']}"

    header = idp.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
    assert "cognito:username" in header, f"expected cognito:username in the CSV header, got {header}"

    # StartUserImportJob requires an actual CSV to have been uploaded to the
    # job's pre-signed S3 URL first; without it, real Cognito rejects the start
    # with PreconditionNotMetException ("No csv file was uploaded for ..."). Build
    # a minimal valid row (cognito:username + cognito:mfa_enabled are the only
    # required columns) and PUT it to the pre-signed URL before starting.
    _upload_import_csv(ctx, job["PreSignedUrl"], header, ctx.unique_name("sim2real-imported-"))

    # StartUserImportJob validates the CloudWatchLogsRoleArn's permissions at call
    # time; the role/inline-policy just created above can take a little while to
    # propagate through IAM, so real Cognito can transiently reject the start with
    # PreconditionNotMetException ("The configured Cloudwatch Logs Role is missing
    # ..."). Poll with bounded retries instead of asserting success on the first try.
    started = _retry_start_import_job(idp, pool_id, job_id)
    # A one-row import can already have finished by the time the start response is built.
    assert started["Status"] in ("Pending", "InProgress", "Succeeded"), (
        f"expected StartUserImportJob to move the job to Pending/InProgress/Succeeded, got {started['Status']}"
    )

    # Real Cognito can leave a just-started job in "Pending" noticeably longer
    # than a few seconds before it flips to "InProgress" (queueing/scheduling
    # delay on the actual import worker) -- 30s was too tight a bound and
    # observed real Cognito still reporting "Pending" at that point. Give this
    # a much more generous bound instead of failing fast.
    described_running = _poll_until(
        lambda: idp.describe_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"],
        lambda j: j["Status"] in ("InProgress", "Stopping", "Stopped", "Failed", "Succeeded"),
        timeout_s=300.0,
        interval_s=3.0,
        description="import job to leave Pending",
    )
    assert described_running["Status"] != "Pending", (
        "expected the started job to leave Pending within the poll window, it did not"
    )

    listed = idp.list_user_import_jobs(UserPoolId=pool_id, MaxResults=10)["UserImportJobs"]
    assert any(j["JobId"] == job_id for j in listed), (
        f"expected job {job_id} to appear in ListUserImportJobs, got {[j['JobId'] for j in listed]}"
    )

    if described_running["Status"] == "InProgress":
        for attempt in range(5):
            try:
                idp.stop_user_import_job(UserPoolId=pool_id, JobId=job_id)
                break
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "TooManyRequestsException" and attempt < 4:
                    time.sleep(2.0)
                    continue
                if code != "PreconditionNotMetException":
                    raise
                # The one-row job can finish between the read and the stop; the documented
                # wrong-state refusal is acceptable only when the job is in fact no longer running.
                now = idp.describe_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"]
                if now["Status"] not in ("Succeeded", "Failed"):
                    raise AssertionError(
                        f"StopUserImportJob refused a job reading {now['Status']!r}: {exc}"
                    ) from exc
                break

    final = _poll_until(
        lambda: idp.describe_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"],
        lambda j: j["Status"] in ("Stopped", "Failed", "Succeeded"),
        timeout_s=60.0,
        interval_s=2.0,
        description="import job to reach a terminal state",
    )
    assert final["Status"] in ("Stopped", "Failed", "Succeeded"), (
        f"expected the job to reach a terminal state after StopUserImportJob, got {final['Status']}"
    )
    if final["Status"] == "Succeeded":
        assert final["ImportedUsers"] == 1, (
            f"expected the one-row import to report ImportedUsers 1, got {final.get('ImportedUsers')!r}"
        )

    listed_final = idp.list_user_import_jobs(UserPoolId=pool_id, MaxResults=10)["UserImportJobs"]
    final_listed = next(j for j in listed_final if j["JobId"] == job_id)
    assert final_listed["Status"] == final["Status"], (
        f"ListUserImportJobs disagrees with DescribeUserImportJob on final status: "
        f"{final_listed['Status']!r} != {final['Status']!r}"
    )


def _upload_import_csv(ctx, presigned_url, header, username):
    """Build a minimal valid import CSV and PUT it to the job's pre-signed S3 URL.

    cognito:username and cognito:mfa_enabled are the only mandatory columns; every
    other column in the header may be left blank.
    """
    row = []
    for col in header:
        if col == "cognito:username":
            row.append(username)
        elif col == "cognito:mfa_enabled":
            row.append("false")
        else:
            row.append("")
    csv_body = ",".join(header) + "\r\n" + ",".join(row) + "\r\n"

    _url, _route = ctx.endpoint_route(presigned_url)
    req = urllib.request.Request(
        _url,
        data=csv_body.encode("utf-8"),
        method="PUT",
        headers={**({
            "Content-Type": "text/csv",
            "x-amz-server-side-encryption": "aws:kms",
        }), **_route},
    )
    with urllib.request.urlopen(req) as resp:
        if resp.status not in (200, 204):
            raise AssertionError(f"CSV upload to pre-signed URL failed with status {resp.status}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last={last!r}")


def _retry_create_import_job(idp, pool_id, job_name, role_arn, timeout_s=30.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return idp.create_user_import_job(
                UserPoolId=pool_id, JobName=job_name, CloudWatchLogsRoleArn=role_arn
            )["UserImportJob"]
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            time.sleep(2.0)
    raise last_exc


def _retry_start_import_job(idp, pool_id, job_id, timeout_s=30.0):
    """Bounded poll for IAM propagation lag on the job's CloudWatchLogsRoleArn."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return idp.start_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"]
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] != "PreconditionNotMetException":
                raise
            time.sleep(3.0)
    raise last_exc


def _safe_delete_role_policy(iam, role_name, policy_name):
    from botocore.exceptions import ClientError

    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_import_log_groups(ctx, pool_id):
    """Cognito creates a /aws/cognito/userpools/<pool id>/<pool name> log group for the
    pool's import jobs; the pool is this check's, so every group under its id is too."""
    logs = ctx.client("logs")
    prefix = f"/aws/cognito/userpools/{pool_id}/"
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=prefix):
        for group in page["logGroups"]:
            try:
                logs.delete_log_group(logGroupName=group["logGroupName"])
            except logs.exceptions.ResourceNotFoundException:
                pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
