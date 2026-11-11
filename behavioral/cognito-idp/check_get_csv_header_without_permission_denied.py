"""get-csv-header-without-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-csv-header-without-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCSVHeader from an IAM principal with no policies is denied with AccessDeniedException,
    and granting that principal a policy scoped to the pool's ARN makes the same call succeed,
    proving the denial was IAM authorization."""
    cognito = ctx.client("cognito-idp")
    iam = ctx.client("iam")

    pool = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-csvhdr-pool-"))[
        "UserPool"
    ]
    pool_id = pool["Id"]
    pool_arn = pool["Arn"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    # Positive control: the admin-credentialed client (full access) can call GetCSVHeader.
    control = cognito.get_csv_header(UserPoolId=pool_id)
    assert "cognito:username" in control["CSVHeader"], control["CSVHeader"]

    # An IAM principal with zero attached policies -- no allow for cognito-idp:*.
    user_name = ctx.unique_name("sim2real-csvhdr-iamuser-")
    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(
            UserName=user_name, AccessKeyId=key["AccessKeyId"]
        )
    )

    restricted = ctx.client(
        "cognito-idp",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    code, message = _poll_for_denial(restricted, pool_id)
    assert code == "AccessDeniedException", code
    expected = (
        f"User: {user_arn} is not authorized to perform: cognito-idp:GetCSVHeader on resource: "
        f"{pool_arn} because no identity-based policy allows the cognito-idp:GetCSVHeader action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Restore: grant this exact principal an identity policy scoped to this exact pool,
    # then the identical call must now succeed with the same CSV header the admin saw.
    policy_name = ctx.unique_name("sim2real-csvhdr-allow-")
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "cognito-idp:GetCSVHeader",
                        "Resource": pool_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
    )

    allowed = _poll_for_allow(restricted, pool_id)
    assert allowed["CSVHeader"] == control["CSVHeader"], (
        allowed["CSVHeader"],
        control["CSVHeader"],
    )


def _poll_for_denial(restricted_client, pool_id: str, timeout_s: float = 60.0) -> tuple[str, str]:
    """New IAM credentials take a few seconds to propagate; poll until the call
    stabilizes on a definitive authorization decision rather than a transient
    'security token invalid' error, and fail hard if it ever actually succeeds."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            resp = restricted_client.get_csv_header(UserPoolId=pool_id)
            raise AssertionError(
                f"expected AccessDeniedException but call succeeded: {resp}"
            )
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            if last_code == "AccessDeniedException":
                return last_code, e.response["Error"].get("Message", "")
            time.sleep(2.0)
    raise AssertionError(f"denial never stabilized within {timeout_s}s; last code={last_code}")


def _poll_for_allow(restricted_client, pool_id: str, timeout_s: float = 60.0) -> dict:
    """The new identity policy also takes a few seconds to propagate; poll until the
    call stops being denied and stabilizes on success."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return restricted_client.get_csv_header(UserPoolId=pool_id)
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            time.sleep(2.0)
    raise AssertionError(f"grant never took effect within {timeout_s}s; last code={last_code}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
