"""get-access-key-info-malformed-key-rejected."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-access-key-info-malformed-key-rejected"
GROUP = 'error-semantics'
SERVICES = ['sts']

@tags("axis:rejection", "cap:unclassified", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AccessKeyId that doesn't match the required format must be rejected."""

    def _unvalidated_client(service="sts"):
        # Disable botocore client-side parameter validation so the SERVICE's own input
        # validation error codes surface instead of a local ParamValidationError.
        return ctx.client(
            service, config=Config(retries={"max_attempts": 1}, parameter_validation=False)
        )

    def _client_error(fn):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(
            f"expected the malformed AccessKeyId to be rejected, but it SUCCEEDED and "
            f"returned {result!r}"
        )

    client = _unvalidated_client()

    # Positive control: GetAccessKeyInfo decodes the id structurally and does not require an
    # active credential, so a syntactically well-formed AccessKeyId must succeed. Without this,
    # the rejection below cannot be told apart from the operation refusing every call.
    user_creds, _ = _iam_user_creds(ctx)
    control_key_id = ctx.client("sts", creds=user_creds).get_session_token()["Credentials"][
        "AccessKeyId"
    ]
    control = client.get_access_key_info(AccessKeyId=control_key_id)
    assert control.get("Account"), (
        f"expected a well-formed AccessKeyId to resolve to an Account, got {control}"
    )

    code, message = _client_error(lambda: client.get_access_key_info(AccessKeyId="short"))
    assert code == "ValidationError", (
        f"expected ValidationError for malformed AccessKeyId, got {code}"
    )
    assert message == (
        "1 validation error detected: Value 'short' at 'accessKeyId' failed to satisfy "
        "constraint: Member must have length greater than or equal to 16"
    ), message


def _iam_user_creds(ctx, policy=None):
    """A fresh IAM user's long-term access key (``creds`` for ctx.client) and the user's ARN.

    GetSessionToken and GetFederationToken take an IAM user's long-term credentials, so the
    check signs them with a user of its own instead of the runner's identity.
    """
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-stsuser-")
    user = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    if policy is not None:
        iam.put_user_policy(
            UserName=user_name, PolicyName="sim2real-behav-sts", PolicyDocument=json.dumps(policy)
        )
        ctx.on_cleanup(
            lambda: iam.delete_user_policy(UserName=user_name, PolicyName="sim2real-behav-sts")
        )
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    key_id = key["AccessKeyId"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key_id))
    creds = {"aws_access_key_id": key_id, "aws_secret_access_key": key["SecretAccessKey"]}
    # A new access key is eventually consistent: poll until STS accepts it.
    probe = ctx.client("sts", creds=creds)
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, max(left - 30.0, 0.0)))
    while True:
        try:
            probe.get_caller_identity()
            return creds, user["Arn"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"the new IAM user's access key never authenticated: {code!r}"
                ) from exc
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
