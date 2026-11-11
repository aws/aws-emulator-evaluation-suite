"""assume-role-external-id-success-with-correct-id."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-external-id-success-with-correct-id"
GROUP = 'credential-issuance'
SERVICES = ['sts']


@tags("axis:happy-path", "cap:c7", "plane:control")
def run(ctx) -> None:
    """AssumeRole with the ExternalId the trust policy requires issues ASIA credentials, and
    GetCallerIdentity through them returns the assumed-role ARN and RoleId:session UserId."""

    sts = ctx.client("sts")
    iam = ctx.client("iam")

    def _client_with_credentials(service, creds):
        return ctx.client(
            service,
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds.get("SessionToken"),
            },
        )

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        while True:
            last = probe()
            if predicate(last):
                return last
            if time.monotonic() >= deadline:
                raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")
            time.sleep(interval_s)

    def _drop_role(role_name):
        iam.delete_role(RoleName=role_name)

    account_id = sts.get_caller_identity()["Account"]
    expected_external_id = ctx.unique_name("sim2real-behav-extid-")
    role_name = ctx.unique_name("sim2real-behav-sts-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": expected_external_id}},
            }
        ],
    }
    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )["Role"]
    ctx.on_cleanup(lambda: _drop_role(role_name))
    role_arn, role_id = created["Arn"], created["RoleId"]

    session_name = ctx.unique_name("sim2real-behav-sess-")

    def _try_assume():
        try:
            return sts.assume_role(
                RoleArn=role_arn, RoleSessionName=session_name, ExternalId=expected_external_id,
            )
        except ClientError:
            return None

    # IAM trust-policy propagation lags CreateRole by seconds; poll the identical call.
    resp = _poll_until(
        _try_assume, lambda r: r is not None, timeout_s=120, interval_s=3.0,
        description=f"role {role_arn} became assumable with the correct ExternalId",
    )

    aru = resp["AssumedRoleUser"]
    expected_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}"
    expected_uid = f"{role_id}:{session_name}"
    assert aru["Arn"] == expected_arn, f"AssumedRoleUser.Arn: expected {expected_arn!r}, got {aru['Arn']!r}"
    assert aru["AssumedRoleId"] == expected_uid, (
        f"AssumedRoleUser.AssumedRoleId: expected {expected_uid!r}, got {aru['AssumedRoleId']!r}"
    )

    creds = resp["Credentials"]
    assert creds["AccessKeyId"].startswith("ASIA"), (
        f"temporary AssumeRole access key id must be in the ASIA class; got {creds['AccessKeyId'][:4]!r}"
    )
    assert isinstance(creds.get("SecretAccessKey"), str) and creds["SecretAccessKey"], (
        "AssumeRole must return a non-empty SecretAccessKey"
    )
    assert isinstance(creds.get("SessionToken"), str) and creds["SessionToken"], (
        "AssumeRole must return a non-empty SessionToken"
    )

    derived = _client_with_credentials("sts", creds)

    def _identity_or_none():
        try:
            return derived.get_caller_identity()
        except ClientError:
            return None

    identity = _poll_until(
        _identity_or_none, lambda r: r is not None,
        timeout_s=120, interval_s=2.0,
        description="GetCallerIdentity through the assumed-role credentials succeeded",
    )

    assert identity["Account"] == account_id, (identity["Account"], account_id)
    assert identity["Arn"] == expected_arn, (
        "GetCallerIdentity in the assumed-role session must return the sts assumed-role ARN "
        f"{expected_arn!r}, not the iam role ARN; got {identity['Arn']!r}"
    )
    assert identity["Arn"] != role_arn, (
        f"GetCallerIdentity must not echo the role's iam ARN back as the caller identity: {identity['Arn']!r}"
    )
    assert identity["UserId"] == expected_uid, (
        f"GetCallerIdentity.UserId: expected {expected_uid!r}, got {identity['UserId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
