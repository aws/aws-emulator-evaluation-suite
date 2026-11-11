"""start-access-request-nonexistent-resource-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-access-request-nonexistent-resource-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartAccessRequest from a role without ssm:StartAccessRequest is refused AccessDenied naming
    its session and the target instance ARN; the permitted caller's identical request is not."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-ssm-no-perms-access-req-")
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
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    session_name = ctx.unique_name("sim2real-session-")
    creds = _assume_role_with_retry(sts, role_arn, session_name)

    admin_ssm = ctx.client("ssm")
    restricted_ssm = ctx.client(
        "ssm",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    bogus_instance_id = "i-" + "0" * 17
    targets = [{"Key": "InstanceIds", "Values": [bogus_instance_id]}]

    # Positive control: the same request with permitted credentials must not be AccessDenied.
    admin_code, admin_message = _error_retry_unrecognized(
        lambda: admin_ssm.start_access_request(
            Reason="sim2real behavioral check: positive control (permitted caller)",
            Targets=targets,
        )
    )
    assert admin_code != "AccessDeniedException", (
        "expected the permission-holding caller to clear IAM authorization for "
        f"StartAccessRequest (any outcome other than AccessDeniedException), got "
        f"{admin_code!r} -- identical to the restricted caller below, so the denial "
        "there cannot be attributed specifically to the missing IAM permission"
    )

    code, message = _error_retry_unrecognized(
        lambda: restricted_ssm.start_access_request(
            Reason="sim2real behavioral check: nonexistent target",
            Targets=targets,
        )
    )
    assert code == "AccessDeniedException", code
    assert message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not "
        "authorized to perform: ssm:StartAccessRequest on resource: "
        f"arn:aws:ec2:{ctx.region}:{account_id}:instance/{bogus_instance_id} because no "
        "identity-based policy allows the ssm:StartAccessRequest action"
    ), message


def _assume_role_with_retry(sts, role_arn, session_name, attempts=10, delay_s=2.0):
    """Retry AssumeRole until the new role's trust policy has propagated."""
    last_exc = None
    for _ in range(attempts):
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            return resp["Credentials"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _error_retry_unrecognized(fn, attempts=6, delay_s=2.0):
    """Return fn's error (code, message), retrying while new STS credentials are still
    UnrecognizedClientException. An unexpected success raises."""
    last = None
    for _ in range(attempts):
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response["Error"]
            last = (error["Code"], error.get("Message", ""))
            if last[0] == "UnrecognizedClientException":
                time.sleep(delay_s)
                continue
            return last
        raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
