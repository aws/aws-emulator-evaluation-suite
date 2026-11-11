"""sample-no-iam-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sample-no-iam-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemakerjobruntime"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role with no SageMaker job runtime permissions is denied Sample with AccessDeniedException (exact message),
    while the caller's own credentials on the same nonexistent job get the "could not find job" ValidationException.
    """
    account_id = ctx.account
    job_arn = _job_arn(ctx, account_id)
    trajectory_id = ctx.unique_name("sim2real-sjr-traj-")
    body = b'{"messages": [{"role": "user", "content": "hello"}]}'

    role_arn = _create_role(
        ctx,
        account_id,
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"}
            ],
        },
    )
    restricted = _assume_role_client(ctx, "sagemakerjobruntime", role_arn)

    def _denied_call():
        restricted.sample(JobArn=job_arn, TrajectoryId=trajectory_id, Body=body)

    code, message = _error_code(_denied_call)
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected = f"User: {_session_arn(account_id, role_arn)} is not authorized to perform: sagemaker:Sample on resource: {job_arn} because no identity-based policy allows the sagemaker:Sample action"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    admin = ctx.client("sagemakerjobruntime")

    def _control_call():
        admin.sample(JobArn=job_arn, TrajectoryId=trajectory_id, Body=body)

    control_code, control_message = _error_code(_control_call)
    assert control_code == "ValidationException", (
        f"expected ValidationException ('could not find job') for the "
        f"fully-permissioned control call, got {control_code}"
    )
    expected_control = f"Could not find job with jobArn {job_arn}"
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
    seconds to propagate -- see the IAM troubleshooting guide's note on
    eventual consistency), so poll sts:AssumeRole until it succeeds rather
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
