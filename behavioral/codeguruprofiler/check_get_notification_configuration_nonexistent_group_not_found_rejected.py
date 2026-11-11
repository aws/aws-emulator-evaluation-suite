"""get-notification-configuration-nonexistent-group-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-notification-configuration-nonexistent-group-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["codeguruprofiler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetNotificationConfiguration on a never-created group fails with ResourceNotFoundException and its exact
    message, while on a real group with no channels it returns an empty channel list.
    """
    cgp = ctx.client("codeguruprofiler")
    missing_name = ctx.unique_name("sim2real-cgp-missing-")
    real_name = ctx.unique_name("sim2real-cgp-real-")
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=real_name))

    code, message = _error_code(
        lambda: cgp.get_notification_configuration(profilingGroupName=missing_name)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-created profiling group, got {code!r}"
    )
    expected_message = (
        f"Profiling group not found with accountId: {ctx.account}, name: {missing_name}."
    )
    assert message == expected_message, (message, expected_message)

    cgp.create_profiling_group(profilingGroupName=real_name, tags={"sim2real": "audit"})
    config = cgp.get_notification_configuration(profilingGroupName=real_name)
    channels = config["notificationConfiguration"].get("channels", [])
    assert channels == [], f"expected no channels on a freshly created group, got {channels!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
