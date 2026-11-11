"""get-application-after-delete-not-found."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-application-after-delete-not-found"
GROUP = "overly-permissive"
SERVICES = ["appintegrations"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteApplication, GetApplication on the same Arn fails with ResourceNotFoundException."""
    appi = ctx.client("appintegrations")

    # Positive control: an untouched sibling application remains gettable throughout.
    control_name = ctx.unique_name("sim2real-app-control-")
    control_namespace = ctx.unique_name("sim2real-ns-control-")
    control = appi.create_application(
        Name=control_name,
        Namespace=control_namespace,
        ApplicationSourceConfig={
            "ExternalUrlConfig": {"AccessUrl": "https://example.com/control"}
        },
    )
    control_arn = control["Arn"]
    ctx.on_cleanup(lambda: appi.delete_application(Arn=control_arn))

    target_name = ctx.unique_name("sim2real-app-target-")
    target_namespace = ctx.unique_name("sim2real-ns-target-")
    target = appi.create_application(
        Name=target_name,
        Namespace=target_namespace,
        ApplicationSourceConfig={
            "ExternalUrlConfig": {"AccessUrl": "https://example.com/target"}
        },
    )
    target_arn = target["Arn"]
    def _cleanup_target() -> None:
        try:
            appi.delete_application(Arn=target_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_target)

    appi.delete_application(Arn=target_arn)

    expected_message = f"Could not find Application with identifier: {target_arn}."
    code, message = _client_error(lambda: appi.get_application(Arn=target_arn))
    assert code == "ResourceNotFoundException", (
        f"expected GetApplication on a deleted Arn to raise ResourceNotFoundException, got {code!r}"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # A mutation on the dead id must also fail, not just the read.
    update_code, update_message = _client_error(
        lambda: appi.update_application(Arn=target_arn, Description="post-delete-update")
    )
    assert update_code == "ResourceNotFoundException", (
        "expected UpdateApplication on a deleted Arn to raise ResourceNotFoundException, "
        f"got {update_code!r}"
    )
    assert update_message == expected_message, f"expected {expected_message!r}, got {update_message!r}"

    # The positive control is unaffected by the deletion of the target.
    still_there = appi.get_application(Arn=control_arn)
    assert still_there["Name"] == control_name, (
        f"expected control application {control_name!r} to remain gettable, got {still_there!r}"
    )


def _client_error(fn: Any) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
