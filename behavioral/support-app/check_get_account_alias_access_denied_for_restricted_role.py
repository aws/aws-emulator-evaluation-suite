"""get-account-alias-access-denied-for-restricted-role."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-account-alias-access-denied-for-restricted-role"
GROUP = "overly-permissive"
SERVICES = ["support-app"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAccountAlias from a role with no permission policy fails with AccessDeniedException and the
    exact message, while the same call with the caller's own credentials succeeds."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account_id = ctx.account
    role_name = ctx.unique_name("sim2real-supportapp-noperm-")

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
        Tags=[{"Key": "sim2real", "Value": "get-account-alias-access-denied-for-restricted-role"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    session_name = ctx.unique_name("sim2real-sess-")
    creds = _assume_role_with_retry(sts, role_arn, session_name)
    restricted_client = ctx.client(
        "support-app",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    # IAM's propagation of a freshly-assumed session can lag briefly behind the
    # role's creation, surfacing as UnrecognizedClientException rather than the
    # steady-state AccessDeniedException; poll until the deny is actually
    # enforced (or a generous deadline elapses) instead of asserting on the
    # first try.
    deadline = time.monotonic() + 60
    code = message = None
    while time.monotonic() < deadline:
        code, message = _error(lambda: restricted_client.get_account_alias())
        if code == "AccessDeniedException":
            break
        time.sleep(5)
    assert code == "AccessDeniedException", f"unexpected code: {code}"
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not "
        "authorized to perform: supportapp:GetAccountAlias on resource: "
        f"arn:aws:supportapp:{ctx.region}:{account_id}:/control/get-account-alias because no "
        "identity-based policy allows the supportapp:GetAccountAlias action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the caller's own (permitted) credentials still succeed
    # with the identical call, in the same run.
    ctx.client("support-app").get_account_alias()


def _error(fn):
    """Call fn(); return its botocore error (code, message). A SUCCESS raises: the check
    needs the call refused, and a permissive target must fail loudly."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _assume_role_with_retry(sts_client, role_arn: str, session_name: str, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            return resp["Credentials"]
        except ClientError as e:
            last_err = e
            time.sleep(2)
    raise AssertionError(f"could not assume freshly-created role in time: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
