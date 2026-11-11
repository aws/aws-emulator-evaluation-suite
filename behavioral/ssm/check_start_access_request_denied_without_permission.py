"""start-access-request-denied-without-permission."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-access-request-denied-without-permission"
GROUP = "error-semantics"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartAccessRequest by a role with no permissions policy fails with AccessDeniedException and
    the exact denial naming the role session, while the caller's own SSM read answers."""
    ssm = ctx.client("ssm")
    targets = [{"Key": "InstanceIds", "Values": ["i-0000000000000000"]}]

    role_arn = _create_restricted_role(ctx, "start-access-request")
    creds = _assume_role(ctx, role_arn)
    restricted_ssm = _client_with_creds(ctx, "ssm", creds)

    code, message = _error_retry_unrecognized(
        lambda: restricted_ssm.start_access_request(
            Reason="sim2real-behavioral permission negative", Targets=targets
        )
    )
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for a no-permissions caller, got {code!r}"
    )
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    assert message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_arn.split('/')[-1]}/"
        "sim2real-behavioral-check is not authorized to perform: ssm:StartAccessRequest on "
        f"resource: arn:aws:ec2:{ctx.region}:{account_id}:instance/i-0000000000000000 because "
        "no identity-based policy allows the ssm:StartAccessRequest action"
    ), message

    # Positive control: the caller's own credentials can still reach the SSM API
    # (an operation that does not depend on the just-in-time node access feature gate),
    # proving the denial above is specific to the restricted principal and not a broken
    # client/endpoint/account.
    resp = ssm.describe_instance_information(MaxResults=5)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"positive control failed: {resp['ResponseMetadata']}"
    )


def _error_retry_unrecognized(fn, attempts=6, delay_s=2.0):
    """Freshly minted STS credentials can briefly be rejected as unrecognized while they
    propagate; retry the call itself (not the assertion) until credentials are live, then
    return the resulting error (code, message). An unexpected SUCCESS raises."""
    last = None
    for _ in range(attempts):
        try:
            result = fn()
        except ClientError as e:
            error = e.response["Error"]
            last = (error["Code"], error.get("Message", ""))
            if last[0] == "UnrecognizedClientException":
                time.sleep(delay_s)
                continue
            return last
        raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")
    return last


def _create_restricted_role(ctx, suffix):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name(f"sim2real-ssm-restricted-{suffix}-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Arn"]


def _assume_role(ctx, role_arn, timeout_s=30.0, interval_s=2.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behavioral-check")
            return resp["Credentials"]
        except ClientError as e:
            last_error = e
            time.sleep(interval_s)
    raise AssertionError(f"could not assume {role_arn} within {timeout_s}s: {last_error}")


def _client_with_creds(ctx, service, creds):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
