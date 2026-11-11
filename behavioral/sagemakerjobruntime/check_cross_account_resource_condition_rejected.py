"""cross-account-resource-condition-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cross-account-resource-condition-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemakerjobruntime"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Sample through a role allowed only for jobs in the caller's own account is denied with
    AccessDeniedException (exact message) for a JobArn in another account, while the same call on the
    caller's account fails job lookup with ValidationException (exact message).
    """
    account_id = ctx.account
    other_account_id = "999999999999" if account_id != "999999999999" else "888888888888"
    trajectory_id = ctx.unique_name("sim2real-sjr-traj-")
    body = b'{"messages": [{"role": "user", "content": "hello"}]}'

    role_arn = _create_role(
        ctx,
        account_id,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sagemaker:Sample",
                    "Resource": "arn:aws:sagemaker:*:*:job/*",
                    "Condition": {
                        "StringEquals": {"aws:ResourceAccount": "${aws:PrincipalAccount}"}
                    },
                }
            ],
        },
    )
    restricted = _assume_role_client(ctx, "sagemakerjobruntime", role_arn)

    cross_account_job_arn = _job_arn(ctx, other_account_id)

    def _denied_call():
        restricted.sample(JobArn=cross_account_job_arn, TrajectoryId=trajectory_id, Body=body)

    code, message = _error_code(_denied_call)
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected = f"User: {_session_arn(account_id, role_arn)} is not authorized to access this resource"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    own_account_job_arn = _job_arn(ctx, account_id)

    def _control_call():
        restricted.sample(JobArn=own_account_job_arn, TrajectoryId=trajectory_id, Body=body)

    control_code, control_message = _error_code(_control_call)
    assert control_code == "ValidationException", (
        f"expected the same-account call to clear the resource condition and "
        f"reach the job-lookup validation layer, got {control_code}"
    )
    expected_control = f"Could not find job with jobArn {own_account_job_arn}"
    assert control_message == expected_control, (
        f"expected message {expected_control!r}, got {control_message!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _job_arn(ctx, account_id, job_name=None, job_type="AgentRFT"):
    name = job_name or ctx.unique_name("sim2real-sjr-job-")
    return f"arn:aws:sagemaker:{ctx.region}:{account_id}:job/{job_type}/{name}"


def _session_arn(account_id, role_arn):
    return f"arn:aws:sts::{account_id}:assumed-role/{role_arn.rsplit('/', 1)[-1]}/sim2real-sjr-session"


def _client_with_credentials(ctx, service, creds):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _create_role(ctx, account_id, policy_document):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sjr-role-")
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
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sjr-policy-")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _assume_role_client(ctx, service, role_arn, timeout_s=60.0, interval_s=3.0):
    """IAM role/policy changes are eventually consistent (can take several
    seconds to propagate), so poll sts:AssumeRole until it succeeds rather
    than failing on the first attempt."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-sjr-session")[
                "Credentials"
            ]
            return _client_with_credentials(ctx, service, creds)
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role {role_arn} in time: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
