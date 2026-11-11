"""get-recommendations-missing-iam-permission-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-recommendations-missing-iam-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["personalize-runtime"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role without personalize:GetRecommendations gets AccessDeniedException with its exact message,
    while the caller's own identical call reaches the lookup and gets InvalidInputException with its
    exact message."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-personalize-rt-denied-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    # deliberately does NOT include personalize:GetRecommendations
    limited_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "personalize:DescribeCampaign", "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="limited", PolicyDocument=json.dumps(limited_policy))

    session_name = ctx.unique_name("sess-")
    creds = _assume_role_with_retry(sts, role_arn, session_name)

    base = ctx.client("personalize-runtime")
    restricted_rt = ctx.client(
        "personalize-runtime",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    user_id = ctx.unique_name("user-")
    bogus_campaign_arn = (
        f"arn:aws:personalize:{ctx.region}:{account_id}:campaign/"
        f"{ctx.unique_name('sim2real-personalize-nope-')}"
    )

    code, message = _error_code(
        lambda: restricted_rt.get_recommendations(campaignArn=bogus_campaign_arn, userId=user_id)
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not authorized "
        f"to perform: personalize:GetRecommendations on resource: {bogus_campaign_arn} because no "
        "identity-based policy allows the personalize:GetRecommendations action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: the ambient (unrestricted) credentials for the same nonexistent
    # campaign reach business logic and report InvalidInputException.
    code2, message2 = _error_code(lambda: base.get_recommendations(campaignArn=bogus_campaign_arn, userId=user_id))
    assert code2 == "InvalidInputException", f"expected InvalidInputException, got {code2}"
    expected2 = f"{bogus_campaign_arn} does not exist or is not active yet."
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call SUCCEEDED: {result!r}")


def _assume_role_with_retry(sts, role_arn, session_name, attempts=8, delay_s=5):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(attempts):
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            return resp["Credentials"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="limited")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
