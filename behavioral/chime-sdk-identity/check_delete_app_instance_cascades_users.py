"""delete-app-instance-cascades-users."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-app-instance-cascades-users"
GROUP = "state"
SERVICES = ["chime-sdk-identity"]
FORBIDDEN_MESSAGE = "You are not allowed to make this request."


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAppInstance removes the AppInstance and cascades to its AppInstanceUsers."""
    # chime-sdk-identity's control plane is us-east-1 only, so the client pins that region.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    name = ctx.unique_name("sim2real-chime-ai-")
    arn = client.create_app_instance(
        Name=name,
        Metadata="",
        ClientRequestToken=uuid.uuid4().hex,
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )["AppInstanceArn"]
    # Deletion happens inline below; make cleanup idempotent against that.
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: client.delete_app_instance(AppInstanceArn=arn)))

    user_arn = client.create_app_instance_user(
        AppInstanceArn=arn,
        AppInstanceUserId=ctx.unique_name("user-"),
        Name="cascade-user",
        ClientRequestToken=uuid.uuid4().hex,
    )["AppInstanceUserArn"]

    # Positive control: both are independently readable before deletion.
    before_instance = client.describe_app_instance(AppInstanceArn=arn)["AppInstance"]
    assert before_instance["AppInstanceArn"] == arn, (
        f"expected describe_app_instance to echo {arn}, got {before_instance.get('AppInstanceArn')}"
    )
    before_user = client.describe_app_instance_user(AppInstanceUserArn=user_arn)["AppInstanceUser"]
    assert before_user["AppInstanceUserArn"] == user_arn, (
        f"expected describe_app_instance_user to echo {user_arn}, got {before_user.get('AppInstanceUserArn')}"
    )

    client.delete_app_instance(AppInstanceArn=arn)

    # Measured on real AWS, not guessed: once the AppInstance itself is gone, describing it by
    # its (now dead) ARN is refused ForbiddenException, not the generic BadRequestException
    # other Describe* not-found cases use -- the deleted AppInstance can no longer authorize
    # a read against its own ARN at all.
    _wait_for_not_found(lambda: client.describe_app_instance(AppInstanceArn=arn), "ForbiddenException")
    _wait_for_not_found(
        lambda: client.describe_app_instance_user(AppInstanceUserArn=user_arn), "ForbiddenException"
    )

    # Gone means unusable too: a mutation against the cascaded-away user must also fail,
    # not just its read.
    mutate_code, mutate_message = _error(
        lambda: client.update_app_instance_user(
            AppInstanceUserArn=user_arn, Name="ghost", Metadata=""
        )
    )
    assert mutate_code == "ForbiddenException", (
        f"expected UpdateAppInstanceUser on a cascaded-away user to fail ForbiddenException, "
        f"got {mutate_code}"
    )
    assert mutate_message == FORBIDDEN_MESSAGE, (
        f"expected message {FORBIDDEN_MESSAGE!r}, got {mutate_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises: accepting
    a call AWS refuses is a distinct failure from returning the wrong error code."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn) -> None:
    """A deleted AppInstance answers NotFoundException or the ForbiddenException asserted above;
    any other failure raises."""
    try:
        fn()
    except ClientError as e:
        err = e.response["Error"]
        if err["Code"] == "NotFoundException":
            return
        if err["Code"] != "ForbiddenException" or err.get("Message") != FORBIDDEN_MESSAGE:
            raise


def _wait_for_not_found(
    probe_fn, expected_code: str, timeout_s: float = 90.0, interval_s: float = 3.0
) -> None:
    """Poll probe_fn until it fails with expected_code, then assert the exact message. Success
    while polling means the resource is still describable (the cascade has not landed yet)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            probe_fn()
            last = ("still describable", None)
        except ClientError as e:
            last = (e.response["Error"]["Code"], e.response["Error"].get("Message"))
            if last[0] == expected_code:
                assert last[1] == FORBIDDEN_MESSAGE, (
                    f"expected message {FORBIDDEN_MESSAGE!r}, got {last[1]!r}"
                )
                return
        time.sleep(interval_s)
    raise AssertionError(
        f"expected {expected_code} after cascading delete, but resource stayed describable; "
        f"last result={last}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
