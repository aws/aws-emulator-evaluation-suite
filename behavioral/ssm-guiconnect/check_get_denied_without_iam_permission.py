"""get-denied-without-iam-permission."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-denied-without-iam-permission"
GROUP = "overly-permissive"
SERVICES = ["ssm-guiconnect"]

_NOT_FOUND = "The following  resource cannot be found: 'ConnectionRecordingPreferences'"
_IAM_DENIED_GET = (
    "User: {user_arn} is not authorized to perform: ssm-guiconnect:GetConnectionRecordingPreferences on resource: "
    "arn:{partition}:ec2:{region}:{account}:instance/* because no identity-based policy allows the "
    "ssm-guiconnect:GetConnectionRecordingPreferences action"
)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A principal with no ssm-guiconnect IAM permissions gets AccessDeniedException on Get
    rather than a not-found or a payload, and after an ssm-guiconnect allow policy is
    attached the same call reaches the permissioned caller's outcome."""
    guiconnect = ctx.client("ssm-guiconnect")
    iam = ctx.client("iam")

    # positive control: the check's own permissioned principal is not denied at all
    normal_code, normal_message = _error(lambda: guiconnect.get_connection_recording_preferences())
    assert normal_code == "ResourceNotFoundException", (
        f"the properly-permissioned caller should not be access-denied, got {normal_code}"
    )
    assert normal_message == _NOT_FOUND, f"unexpected ResourceNotFoundException message: {normal_message!r}"

    user_name = ctx.unique_name("sim2real-guic-nodeny2-")
    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    restricted = ctx.client(
        "ssm-guiconnect",
        creds={"aws_access_key_id": key["AccessKeyId"], "aws_secret_access_key": key["SecretAccessKey"]},
    )

    # break: zero ssm-guiconnect permissions
    code, message = _poll_error(
        lambda: restricted.get_connection_recording_preferences(),
        transient=("InvalidClientTokenId", "UnrecognizedClientException"),
        timeout_s=30.0,
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    partition, user_account = user_arn.split(":")[1], user_arn.split(":")[4]
    expected = _IAM_DENIED_GET.format(user_arn=user_arn, partition=partition, region=ctx.region, account=user_account)
    assert message == expected, f"expected IAM denial message {expected!r}, got {message!r}"

    # restore: grant the same principal an ssm-guiconnect allow policy; the identical call must
    # then reach the same outcome as the positive control above
    policy_name = ctx.unique_name("sim2real-guic-allow-")
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "ssm-guiconnect:*", "Resource": "*"}],
        }),
    )
    ctx.on_cleanup(lambda: _delete_user_policy_safely(iam, user_name, policy_name))

    restored_code, restored_message = _poll_error(
        lambda: restricted.get_connection_recording_preferences(),
        transient=("InvalidClientTokenId", "UnrecognizedClientException", "AccessDeniedException"),
        timeout_s=90.0,
    )
    assert (restored_code, restored_message) == (normal_code, normal_message), (
        f"granting ssm-guiconnect:* must restore the identical call to the same outcome as the "
        f"suite's permissioned principal, got {restored_code!r}: {restored_message!r}"
    )


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _poll_error(fn, transient: tuple[str, ...], timeout_s: float) -> tuple[str, str]:
    """Poll ``fn`` past the ``transient`` codes and return the first other (code, message).

    A call that succeeds fails the check; so does a ``transient`` code that outlasts ``timeout_s``.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            fn()
        except ClientError as e:
            last = (e.response["Error"]["Code"], e.response["Error"].get("Message", ""))
            if last[0] not in transient:
                return last
        else:
            raise AssertionError("expected the call to be refused, but it succeeded")
        time.sleep(2.0)
    raise AssertionError(f"still seeing a transient refusal after {timeout_s}s; last observed {last!r}")


def _delete_user_policy_safely(iam, user_name: str, policy_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
