"""athena-missing-s3-output-bucket-permission-negative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "athena-missing-s3-output-bucket-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A query whose role denies s3:PutObject on the output bucket ends FAILED and writes no result
    object, while the same role querying into an allowed bucket succeeds."""
    allow_bucket = _create_bucket(ctx, "roleallow")
    deny_bucket = _create_bucket(ctx, "roledeny")

    role_name, role_arn = _create_role_with_deny(ctx, allow_bucket, deny_bucket)
    creds = _assume_role_with_retry(ctx, role_arn)["Credentials"]
    role_athena = _client_with_creds(ctx, "athena", creds)

    # Negative: output location on the bucket the role is explicitly denied to PutObject on.
    deny_prefix = "results/"
    qid, state, exec_resp = _run_query_with_retry(
        role_athena,
        query="SELECT 'sim2real-denied' AS marker",
        output_location=f"s3://{deny_bucket}/{deny_prefix}",
    )
    assert state == "FAILED", f"expected FAILED, got {state}: {exec_resp['Status']}"
    reason = exec_resp["Status"].get("StateChangeReason", "")
    assert reason == (
        f"Access denied when writing to location: s3://{deny_bucket}/{deny_prefix}{qid}.csv"
    ), reason

    s3 = ctx.client("s3")
    deny_head_code, deny_head_message = _error_code(
        lambda: s3.head_object(Bucket=deny_bucket, Key=f"{deny_prefix}{qid}.csv")
    )
    assert deny_head_code == "404", (
        f"a FAILED execution must never leave a result object at the denied output location; "
        f"expected head_object to 404, got {deny_head_code!r}"
    )
    assert deny_head_message == "Not Found", deny_head_message

    # Positive control: same role, same query, output to the allowed bucket.
    allow_prefix = "results/"
    qid2, state2, exec_resp2 = _run_query_with_retry(
        role_athena,
        query="SELECT 'sim2real-allowed' AS marker",
        output_location=f"s3://{allow_bucket}/{allow_prefix}",
    )
    assert state2 == "SUCCEEDED", f"positive control failed: {exec_resp2['Status']}"
    head = s3.head_object(Bucket=allow_bucket, Key=f"{allow_prefix}{qid2}.csv")
    assert head["ContentLength"] > 0, (
        f"the positive control's result object must be written with real content; "
        f"got ContentLength={head['ContentLength']!r}"
    )


def _error_code(fn) -> tuple[str, str]:
    """fn()'s error code and message; a call that succeeds where a refusal is expected fails."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_bucket(ctx, kind: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-athena-{kind}-").replace("_", "-").lower()
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _create_role_with_deny(ctx, allow_bucket: str, deny_bucket: str):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-athena-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "athena:*", "Resource": "*"},
            {"Effect": "Allow", "Action": "glue:*", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                    "s3:GetObject",
                    "s3:PutObject",
                ],
                "Resource": [
                    f"arn:aws:s3:::{allow_bucket}",
                    f"arn:aws:s3:::{allow_bucket}/*",
                    f"arn:aws:s3:::{deny_bucket}",
                    f"arn:aws:s3:::{deny_bucket}/*",
                ],
            },
            {
                "Effect": "Deny",
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{deny_bucket}/*",
            },
        ],
    }
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    return role_name, role_arn


def _assume_role_with_retry(ctx, role_arn: str, timeout_s: float = 90.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-athena-neg")
        except ClientError as e:
            last_err = e
            time.sleep(3)
    raise AssertionError(f"could not assume role {role_arn}: {last_err}")


def _client_with_creds(ctx, service: str, creds: dict):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _run_query_with_retry(
    athena_client,
    query: str,
    output_location: str,
    timeout_s: float = 120.0,
    setup_timeout_s: float = 60.0,
):
    """Starts the query, retrying only transient AccessDenied on
    StartQueryExecution itself (IAM policy propagation lag) -- not on the
    eventual FAILED execution state, which is the outcome under test."""
    deadline = time.monotonic() + setup_timeout_s
    last_err = None
    qid = None
    while time.monotonic() < deadline:
        try:
            resp = athena_client.start_query_execution(
                QueryString=query, ResultConfiguration={"OutputLocation": output_location}
            )
            qid = resp["QueryExecutionId"]
            break
        except ClientError as e:
            last_err = e
            time.sleep(3)
    if qid is None:
        raise AssertionError(f"could not start query: {last_err}")

    poll_deadline = time.monotonic() + timeout_s
    exec_resp = None
    state = None
    while time.monotonic() < poll_deadline:
        exec_resp = athena_client.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = exec_resp["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return qid, state, exec_resp
        time.sleep(2)
    raise AssertionError(f"query {qid} did not finish in {timeout_s}s, last state {state}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
