"""workgroup-scoped-iam-policy-denies-start-query-execution-on-one-workgroup."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "workgroup-scoped-iam-policy-denies-start-query-execution-on-one-workgroup"
GROUP = "permission-boundary"
SERVICES = ["athena"]

_UNEXPECTED_SUCCESS = "UNEXPECTED_SUCCESS"


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object (Athena writes `<qid>.csv` and `.csv.metadata`), then the bucket."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _wait_terminal(athena, qid, timeout_s=180, interval_s=2):
    """Poll GetQueryExecution to a terminal state; raise on timeout. The scoped grant can admit
    StartQueryExecution before it admits GetQueryExecution, so AccessDeniedException is retried."""
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        try:
            state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDeniedException":
                raise
            state = "AccessDeniedException"
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")


def _error(fn):
    """Return the (Error.Code, Error.Message) raised by fn(), or _UNEXPECTED_SUCCESS twice on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    return _UNEXPECTED_SUCCESS, _UNEXPECTED_SUCCESS


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry that RAISES on timeout, never returning its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not hold within {timeout_s}s; last result {last!r}")


def _assume_role(ctx, role_arn, *, timeout_s=90):
    """Assume `role_arn`, retrying only the not-yet-propagated AccessDenied; raise on timeout."""
    sts = ctx.client("sts")
    session_name = ctx.unique_name("sim2real-behav-sess-")[:60]
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDenied":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"could not assume {role_arn} within {timeout_s}s: {last}")


def _policy_document(region, account_id, results_bucket, workgroup_names):
    """An identity policy granting the Athena query actions only on the named workgroups."""
    wg_arns = [
        f"arn:aws:athena:{region}:{account_id}:workgroup/{name}" for name in workgroup_names
    ]
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AthenaOnNamedWorkgroupsOnly",
                "Effect": "Allow",
                "Action": [
                    "athena:StartQueryExecution",
                    "athena:GetQueryExecution",
                    "athena:GetQueryResults",
                    "athena:StopQueryExecution",
                ],
                "Resource": wg_arns,
            },
            {
                "Sid": "ResultsBucket",
                "Effect": "Allow",
                "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
                "Resource": f"arn:aws:s3:::{results_bucket}",
            },
            {
                "Sid": "ResultsObjects",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:AbortMultipartUpload"],
                "Resource": f"arn:aws:s3:::{results_bucket}/*",
            },
        ],
    }


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role whose policy names one workgroup ARN may StartQueryExecution there but gets
    AccessDeniedException on another, with no execution recorded, until the policy is widened.

    Reference: https://docs.aws.amazon.com/athena/latest/ug/workgroups-iam-policy.html
    """
    admin_athena = ctx.client("athena")
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    results_bucket = _make_bucket(ctx, "sim2real-behav-athena-results-")
    out = f"s3://{results_bucket}/results/"

    granted_wg = ctx.unique_name("sim2real-behav-athena-wg-ok-")
    denied_wg = ctx.unique_name("sim2real-behav-athena-wg-no-")
    for name in (granted_wg, denied_wg):
        admin_athena.create_work_group(
            Name=name,
            Configuration={
                "ResultConfiguration": {"OutputLocation": out},
                "EnforceWorkGroupConfiguration": True,
            },
            Tags=[{"Key": "sim2real", "Value": CHECK},
                  {"Key": "sim2real:managed", "Value": "true"}],
        )
        ctx.on_cleanup(
            lambda n=name: admin_athena.delete_work_group(WorkGroup=n, RecursiveDeleteOption=True))
        state = admin_athena.get_work_group(WorkGroup=name)["WorkGroup"]["State"]
        assert state == "ENABLED", (
            f"both workgroups must be ENABLED so the only difference between the two legs is the "
            f"policy; workgroup {name!r} reported State {state!r}")

    role_name = ctx.unique_name("sim2real-behav-athena-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "athena-workgroup-scope"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name,
        PolicyDocument=json.dumps(
            _policy_document(ctx.region, account_id, results_bucket, [granted_wg])))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    creds = _assume_role(ctx, role_arn)
    as_role = ctx.client("athena", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })
    who = ctx.client("sts", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }).get_caller_identity()
    assert f":assumed-role/{role_name}/" in who["Arn"], (
        f"the second hop must sign as the scoped role, not as the runner; GetCallerIdentity "
        f"reported {who['Arn']!r}")

    sql = "SELECT 1 AS one"

    # Positive control on the granted workgroup; polled because a new inline policy is not
    # instantly effective.
    granted_id_box = {}

    def _try_granted():
        try:
            granted_id_box["qid"] = as_role.start_query_execution(
                QueryString=sql, WorkGroup=granted_wg)["QueryExecutionId"]
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        return _UNEXPECTED_SUCCESS

    outcome = _poll(
        _try_granted, lambda c: c == _UNEXPECTED_SUCCESS, timeout_s=90, interval_s=5,
        description="the scoped inline policy becomes effective for the granted workgroup")
    assert outcome == _UNEXPECTED_SUCCESS, (
        f"the policy grants athena:StartQueryExecution on workgroup {granted_wg!r}, so the real "
        f"signed call must be accepted; got {outcome!r}")
    granted_qid = granted_id_box["qid"]
    granted_state = _wait_terminal(as_role, granted_qid)
    assert granted_state == "SUCCEEDED", (
        f"the control query on the granted workgroup must actually run to SUCCEEDED, got "
        f"{granted_state!r}")

    # Only the workgroup named in the request changes.
    denied_code, denied_message = _error(
        lambda: as_role.start_query_execution(QueryString=sql, WorkGroup=denied_wg))
    assert denied_code == "AccessDeniedException", (
        f"the same identity making the same call with only the workgroup changed to {denied_wg!r} "
        f"must be refused with AccessDeniedException; got {denied_code!r}")
    expected = ("You are not authorized to perform: athena:StartQueryExecution on the resource. "
                "After your AWS administrator or you have updated your permissions, please try again.")
    assert denied_message == expected, f"expected message {expected!r}, got {denied_message!r}"

    denied_ids = admin_athena.list_query_executions(WorkGroup=denied_wg)["QueryExecutionIds"]
    assert denied_ids == [], (
        f"the refused submission must not have created an execution: ListQueryExecutions for "
        f"{denied_wg!r} returned {denied_ids!r}")

    # Restore by widening the policy to both workgroups.
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name,
        PolicyDocument=json.dumps(
            _policy_document(ctx.region, account_id, results_bucket, [granted_wg, denied_wg])))
    restored_box = {}

    def _try_denied():
        try:
            restored_box["qid"] = as_role.start_query_execution(
                QueryString=sql, WorkGroup=denied_wg)["QueryExecutionId"]
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        return _UNEXPECTED_SUCCESS

    # Updating an existing inline policy propagates far more slowly than a role's first policy
    # (observed ~310s), so this poll allows 500s.
    restored = _poll(
        _try_denied, lambda c: c == _UNEXPECTED_SUCCESS, timeout_s=500, interval_s=10,
        description="the widened policy becomes effective for the previously denied workgroup")
    assert restored == _UNEXPECTED_SUCCESS, (
        f"once {denied_wg!r} is named in the policy the identical call must be accepted, proving "
        f"the refusal was the resource scope and not the action or the identity; got {restored!r}")
    restored_qid = restored_box["qid"]
    restored_state = _wait_terminal(as_role, restored_qid)
    assert restored_state == "SUCCEEDED", (
        f"the newly permitted query must run to SUCCEEDED on {denied_wg!r}, got "
        f"{restored_state!r}")
    now_ids = admin_athena.list_query_executions(WorkGroup=denied_wg)["QueryExecutionIds"]
    assert now_ids == [restored_qid], (
        f"the once-denied workgroup must now hold exactly the one execution the widened policy "
        f"allowed ({restored_qid!r}), got {now_ids!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
