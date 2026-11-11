"""get-control-missing-permission-denied."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-control-missing-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["controlcatalog"]

_DENY_MESSAGE = (
    "User: {principal} is not authorized to perform: controlcatalog:GetControl on resource: {control} "
    "because no identity-based policy allows the controlcatalog:GetControl action"
)


def _error_code(fn):
    """Call fn(); return the botocore error code. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected AccessDenied for the unprivileged principal, but the call SUCCEEDED "
        f"and returned {result!r}"
    )


@tags("axis:rejection", "cap:c5", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An IAM principal with no attached policies is denied controlcatalog:GetControl (implicit-deny)."""
    cc = ctx.client("controlcatalog")
    iam = ctx.client("iam")

    # Discover a real, callable control first so the positive control below is meaningful.
    real_arn = cc.list_controls(MaxResults=1)["Controls"][0]["Arn"]

    user_name = ctx.unique_name("sim2real-cc-nopolicy-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    unprivileged = ctx.client(
        "controlcatalog",
        creds={"aws_access_key_id": key["AccessKeyId"], "aws_secret_access_key": key["SecretAccessKey"]},
    )

    # New IAM credentials can take a few seconds to propagate; poll until we get a definitive
    # authorization decision rather than a transient credential-propagation error (botocore
    # surfaces this lag as InvalidClientTokenId OR UnrecognizedClientException OR
    # InvalidAccessKeyId depending on exactly which validation layer sees the not-yet-live key).
    transient_codes = {"InvalidClientTokenId", "UnrecognizedClientException", "InvalidAccessKeyId"}
    deadline = time.monotonic() + 45
    code = message = None
    while time.monotonic() < deadline:
        code, message = _error_code(lambda: unprivileged.get_control(ControlArn=real_arn))
        if code not in transient_codes:
            break
        time.sleep(2)

    assert code == "AccessDeniedException", (
        f"expected an access-denied error for an unprivileged principal, got {code!r}"
    )
    expected = _DENY_MESSAGE.format(principal=f"arn:aws:iam::{ctx.account}:user/{user_name}", control=real_arn)
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Positive control (same file, same resource, privileged credentials): the call succeeds.
    detail = cc.get_control(ControlArn=real_arn)
    assert detail["Arn"] == real_arn, f"expected Arn={real_arn!r}, got {detail.get('Arn')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
