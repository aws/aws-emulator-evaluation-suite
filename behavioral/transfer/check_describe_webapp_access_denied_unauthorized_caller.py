"""describe-webapp-access-denied-unauthorized-caller."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-webapp-access-denied-unauthorized-caller"
GROUP = "error-semantics"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeWebApp on a never-created WebAppId is AccessDeniedException for a zero-permission
    role session and ResourceNotFoundException for the authorized caller, so authorization is
    evaluated before the resource lookup."""
    transfer = ctx.client("transfer")
    bogus_webapp_id = "webapp-" + "0" * 17  # matches ^webapp-[0-9a-f]{17}$, never created

    creds, role_arn, session_name = _assume_low_privilege_role(ctx)
    low_priv_transfer = ctx.client(
        "transfer",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    code, message = _error(lambda: low_priv_transfer.describe_web_app(WebAppId=bogus_webapp_id))
    assert code == "AccessDeniedException", f"expected AccessDeniedException for an unauthorized caller, got {code}"
    partition, account = role_arn.split(":")[1], role_arn.split(":")[4]
    assumed_arn = role_arn.replace(":iam::", ":sts::").replace(":role/", ":assumed-role/") + f"/{session_name}"
    assert message == (
        f"User: {assumed_arn} is not authorized to perform: transfer:DescribeWebApp on resource: "
        f"arn:{partition}:transfer:{ctx.region}:{account}:webapp/{bogus_webapp_id} because no "
        "identity-based policy allows the transfer:DescribeWebApp action"
    ), f"unexpected DescribeWebApp denial message: {message!r}"

    # The authorized caller gets resource absence for the same id instead.
    code2, message2 = _error(lambda: transfer.describe_web_app(WebAppId=bogus_webapp_id))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException for authorized caller, got {code2}"
    assert message2 == "Unknown WebApp", f"unexpected not-found message: {message2!r}"


def _error(fn):
    """Call fn() and return its botocore error (code, message); an unexpected success raises
    rather than surfacing as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _assume_low_privilege_role(ctx):
    """Create a role with only a trust policy, assume it once the trust has propagated, and
    return (temporary credentials, role ARN, session name)."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-transfer-lowpriv-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    session_name = ctx.unique_name("sim2real-session-")[:64]
    deadline = time.monotonic() + 60.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
            return creds, role_arn, session_name
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDenied", "AccessDeniedException"):
                last_exc = exc
                time.sleep(3.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
