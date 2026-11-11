"""remove-region-access-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "remove-region-access-denied"
GROUP = "overly-permissive"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RemoveRegion from a session whose policy explicitly denies ds:RemoveRegion fails with
    AccessDeniedException before directory validation, while the same call from an unrestricted
    principal reaches validation (DirectoryDoesNotExistException)."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    default_ds = ctx.client("ds")

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-ds-deny-role")
    policy_name = f"{role_name}-policy"

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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "ds:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "ds:RemoveRegion", "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(deny_policy))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))

    creds = _assume_role_with_retry(sts, role_arn, ctx.unique_name("sim2real-ds-deny-sess"))

    denied_ds = ctx.client(
        "ds",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    session_arn = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    ).get_caller_identity()["Arn"]

    fake_directory_id = "d-9074657a01"  # syntactically valid (d-[0-9a-f]{10}), does not exist

    denied_code, denied_message, _denied_request = _client_error(
        lambda: denied_ds.remove_region(DirectoryId=fake_directory_id)
    )
    assert denied_code == "AccessDeniedException", (
        f"expected AccessDeniedException for the IAM-denied caller, got {denied_code!r}"
    )
    expected = (
        f"User: {session_arn} is not authorized to perform: ds:RemoveRegion on resource: "
        f"arn:aws:ds:{ctx.region}:{account_id}:directory/{fake_directory_id} "
        f"with an explicit deny in an identity-based policy"
    )
    assert denied_message == expected, (
        f"the IAM-denied RemoveRegion must refuse with {expected!r}, got {denied_message!r}"
    )

    # positive control: without the explicit deny, the identical call reaches normal
    # business-logic validation instead of being blanket-denied
    normal_code, normal_message, normal_request = _client_error(
        lambda: default_ds.remove_region(DirectoryId=fake_directory_id)
    )
    assert normal_code == "DirectoryDoesNotExistException", (
        f"expected DirectoryDoesNotExistException for the unrestricted caller, got {normal_code!r}"
    )
    expected = f"Directory: '{fake_directory_id}' does not exist. : RequestId: {normal_request}"
    assert normal_message == expected, (
        f"the unrestricted RemoveRegion must refuse with {expected!r}, got {normal_message!r}"
    )


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of the ClientError it must raise. An
    unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
        return err.get("Code"), err.get("Message") or "", request_id
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _assume_role_with_retry(sts, role_arn, session_name, timeout_s=60.0, interval_s=3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as e:
            last_exc = e
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role {role_arn} within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
