"""delete-app-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-app-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteApp on an app name that was never created returns ResourceNotFound
    rather than silently succeeding (which would hide a real emulator bug
    where delete is a no-op for any input).
    """
    sm = ctx.client("sagemaker")
    domain_id = "d-" + uuid.uuid4().hex[:12]
    app_name = ctx.unique_name("sim2real-noapp-")[:63]
    user_profile_name = ctx.unique_name("sim2real-nouser-")[:63]

    # DeleteApp requires either SpaceName or UserProfileName be set; supply a
    # (also nonexistent) UserProfileName so the request is well-formed and the
    # rejection we observe is the ResourceNotFound for the missing app/domain,
    # not a ValidationException for an incomplete request.
    code, message = _error_code_and_message(
        lambda: sm.delete_app(
            DomainId=domain_id,
            AppType="JupyterServer",
            AppName=app_name,
            UserProfileName=user_profile_name,
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code}: {message!r}"
    expected_message = (
        f"App [arn:aws:sagemaker:{ctx.region}:{ctx.account}:app/{domain_id}/{user_profile_name}/"
        f"JupyterServer/{app_name}] does not exist."
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Independent read at a different operation: the app is not just rejected by
    # DeleteApp, it genuinely does not exist. Without this, a DeleteApp that always
    # answers ResourceNotFound while DescribeApp reports something else would still
    # pass on the mutating call's own response alone.
    describe_code, describe_message = _error_code_and_message(
        lambda: sm.describe_app(
            DomainId=domain_id,
            AppType="JupyterServer",
            AppName=app_name,
            UserProfileName=user_profile_name,
        )
    )
    assert describe_code == "ResourceNotFound", (
        f"expected ResourceNotFound, got {describe_code}: {describe_message!r}"
    )
    expected_describe = (
        f"App [arn:aws:sagemaker:{ctx.region}:{ctx.account}:app/{domain_id}/{user_profile_name}/"
        f"JupyterServer/{app_name}] does not exist."
    )
    assert describe_message == expected_describe, (
        f"expected {expected_describe!r}, got {describe_message!r}"
    )


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
