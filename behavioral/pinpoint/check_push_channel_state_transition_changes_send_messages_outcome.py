"""push-channel-state-transition-changes-send-messages-outcome."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "push-channel-state-transition-changes-send-messages-outcome"
GROUP = "channel-state"
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


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """SendMessages through a BAIDU address fails for a different, more specific reason
    once the BAIDU channel is enabled than it does while the channel is absent.

    Reference: https://docs.aws.amazon.com/pinpoint/latest/apireference/apps-application-id-messages.html
    """
    pin = ctx.client("pinpoint")
    app_name = ctx.unique_name("sim2real-behav-pushapp-")
    app = pin.create_app(CreateApplicationRequest={"Name": app_name})["ApplicationResponse"]
    app_id = app["Id"]
    ctx.on_cleanup(_teardown(lambda: pin.delete_app(ApplicationId=app_id), "NotFoundException"))

    token = ctx.unique_name("sim2real-behav-baidu-token-")

    def _send():
        return pin.send_messages(
            ApplicationId=app_id,
            MessageRequest={
                "Addresses": {token: {"ChannelType": "BAIDU"}},
                "MessageConfiguration": {"BaiduMessage": {"Body": "sim2real-behav-body"}},
            },
        )["MessageResponse"]["Result"][token]

    before = _send()
    assert before["StatusCode"] == 404, f"expected 404 before enabling BAIDU, got {before!r}"
    assert before["DeliveryStatus"] == "PERMANENT_FAILURE", (
        f"expected PERMANENT_FAILURE before enabling BAIDU, got {before!r}"
    )
    assert before["StatusMessage"] == (
        f"BAIDU channel not found. Please enable the BAIDU channel for this application {app_id}."
    ), f"unexpected pre-enable message {before['StatusMessage']!r}"

    pin.update_baidu_channel(
        ApplicationId=app_id,
        BaiduChannelRequest={
            "Enabled": True,
            "ApiKey": ctx.unique_name("sim2real-behav-baidu-key-"),
            "SecretKey": ctx.unique_name("sim2real-behav-baidu-secret-"),
        },
    )
    ctx.on_cleanup(
        _teardown(lambda: pin.delete_baidu_channel(ApplicationId=app_id), "NotFoundException")
    )

    enabled = pin.get_baidu_channel(ApplicationId=app_id)["BaiduChannelResponse"]
    assert enabled["Enabled"] is True, f"expected the BAIDU channel enabled, got {enabled!r}"

    after = _send()
    assert after["StatusCode"] == 400, (
        f"expected 400 once BAIDU is enabled but the push token is invalid, got {after!r}"
    )
    assert after["DeliveryStatus"] == "PERMANENT_FAILURE", (
        f"expected PERMANENT_FAILURE after enabling BAIDU, got {after!r}"
    )
    payload = json.loads(after["StatusMessage"])
    assert payload["errorMessage"] == "Invalid notification", (
        f"expected an Invalid notification push-provider error, got {payload!r}"
    )
    assert payload["channelType"] == "BAIDU", f"expected channelType BAIDU, got {payload!r}"
    assert before["StatusCode"] != after["StatusCode"], (
        "enabling the channel must change the failure mode, not just its wording"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
