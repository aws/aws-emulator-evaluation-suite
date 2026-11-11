"""delete-app-cascades-channel-configuration."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-app-cascades-channel-configuration"
GROUP = "app-lifecycle"
SERVICES = ["pinpoint"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """Deleting an app removes its channel configuration too: a channel reachable while
    the app exists becomes unreachable, under a different NotFoundException message than
    a configured-but-disabled channel would.

    Reference: https://docs.aws.amazon.com/pinpoint/latest/apireference/apps-application-id-channels-baidu.html
    """
    pin = ctx.client("pinpoint")
    app_name = ctx.unique_name("sim2real-behav-cascadeapp-")
    app_id = pin.create_app(CreateApplicationRequest={"Name": app_name})["ApplicationResponse"][
        "Id"
    ]
    ctx.on_cleanup(_teardown(lambda: pin.delete_app(ApplicationId=app_id), "NotFoundException"))

    pin.update_baidu_channel(
        ApplicationId=app_id,
        BaiduChannelRequest={
            "Enabled": True,
            "ApiKey": ctx.unique_name("sim2real-behav-baidu-key-"),
            "SecretKey": ctx.unique_name("sim2real-behav-baidu-secret-"),
        },
    )
    # Positive control: the channel is reachable while the app still exists.
    before = pin.get_baidu_channel(ApplicationId=app_id)["BaiduChannelResponse"]
    assert before["Enabled"] is True, f"expected the channel enabled before delete, got {before!r}"

    pin.delete_app(ApplicationId=app_id)

    code, message = _error(lambda: pin.get_app(ApplicationId=app_id))
    assert code == "NotFoundException", (
        f"expected NotFoundException for GetApp, got {code}: {message!r}"
    )
    assert message == "Application not found", f"unexpected GetApp message {message!r}"

    code, message = _error(lambda: pin.get_baidu_channel(ApplicationId=app_id))
    assert code == "NotFoundException", (
        f"expected NotFoundException for GetBaiduChannel on a deleted app, got {code}: {message!r}"
    )
    assert message == "Resource not found", (
        f"expected the generic 'Resource not found' once the app itself is gone, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
