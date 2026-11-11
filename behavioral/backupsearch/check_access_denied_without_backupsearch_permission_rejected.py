"""access-denied-without-backupsearch-permission-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "access-denied-without-backupsearch-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["backupsearch"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A caller assuming an IAM role with no attached permissions is rejected by StartSearchJob
    with AccessDeniedException, while the same call using the harness's own (permitted)
    credentials (the positive control, in this file) succeeds."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    bs = ctx.client("backupsearch")

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-bksearch-noperm-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort_delete_role(iam, role_name))

    session_name = ctx.unique_name("sim2real-sess-")
    creds = _assume_role_with_retry(sts, role_arn, session_name)
    denied_client = ctx.client(
        "backupsearch",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    denied_name = ctx.unique_name("sim2real-behav-searchjob-")
    code, message = _error(
        lambda: denied_client.start_search_job(
            Name=denied_name,
            SearchScope={"BackupResourceTypes": ["S3"]},
        )
    )
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for a caller with zero attached IAM permissions, "
        f"got {code!r}"
    )
    region = bs.meta.region_name
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} "
        f"is not authorized to perform: backup-search:StartSearchJob on resource: "
        f"arn:aws:backup-search:{region}:{account_id}:/search-jobs because no identity-based "
        f"policy allows the backup-search:StartSearchJob action"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect absent: the rejected call must not have created a search job under any identity.
    assert _find_job_by_name(bs, denied_name) is None, (
        f"a search job named {denied_name!r} exists despite the creating call being rejected "
        f"with AccessDeniedException"
    )

    # Positive control: the harness's own (permitted) credentials can perform the identical call.
    started = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-"),
        SearchScope={"BackupResourceTypes": ["S3"]},
    )
    job_id = started["SearchJobIdentifier"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))

    # Terminal assertion is an independent read, not the mutating call's own response.
    fetched = bs.get_search_job(SearchJobIdentifier=job_id)
    assert fetched["SearchJobIdentifier"] == job_id, (
        f"expected GetSearchJob to independently confirm the job the permitted caller started; "
        f"got {fetched.get('SearchJobIdentifier')!r} for requested {job_id!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but call succeeded and returned {result!r}")


def _assume_role_with_retry(sts, role_arn: str, session_name: str, *, timeout_s: float = 60.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            return resp["Credentials"]
        except ClientError as err:
            last_err = err
            time.sleep(3.0)
    raise AssertionError(f"could not assume freshly created role in time: {last_err}")


def _find_job_by_name(bs, name: str, *, max_pages: int = 50):
    token = None
    kwargs: dict = {"MaxResults": 1000}
    for _ in range(max_pages):
        if token:
            kwargs["NextToken"] = token
        page = bs.list_search_jobs(**kwargs)
        for job in page.get("SearchJobs", []):
            if job.get("Name") == name:
                return job
        token = page.get("NextToken")
        if not token:
            break
    return None


def _best_effort_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _best_effort_stop(bs, job_id: str) -> None:
    try:
        bs.stop_search_job(SearchJobIdentifier=job_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
