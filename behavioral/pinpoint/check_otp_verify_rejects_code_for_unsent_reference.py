"""otp-verify-rejects-code-for-unsent-reference."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "otp-verify-rejects-code-for-unsent-reference"
GROUP = "otp"
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
    """VerifyOTPMessage answers Valid false for a ReferenceId that never had a code
    delivered through it, whether or not SendOTPMessage was ever called for it.

    Reference: https://docs.aws.amazon.com/pinpoint/latest/apireference/apps-application-id-verify-otp.html
    """
    pin = ctx.client("pinpoint")
    app_name = ctx.unique_name("sim2real-behav-otpapp-")
    app_id = pin.create_app(CreateApplicationRequest={"Name": app_name})["ApplicationResponse"][
        "Id"
    ]
    ctx.on_cleanup(_teardown(lambda: pin.delete_app(ApplicationId=app_id), "NotFoundException"))

    destination = "+12065550100"
    sent_reference = ctx.unique_name("sim2real-behav-otp-ref-sent-")
    unsent_reference = ctx.unique_name("sim2real-behav-otp-ref-unsent-")

    sent = pin.send_otp_message(
        ApplicationId=app_id,
        SendOTPMessageRequestParameters={
            "BrandName": "sim2real-behav",
            "Channel": "SMS",
            "DestinationIdentity": destination,
            "OriginationIdentity": "+12065550199",
            "ReferenceId": sent_reference,
        },
    )["MessageResponse"]["Result"][destination]
    assert sent["DeliveryStatus"] == "PERMANENT_FAILURE", (
        f"expected the sandbox's unowned origination identity to fail delivery, got {sent!r}"
    )

    # The sent reference never actually delivered a code (delivery failed above), so a
    # verify against it must still be rejected, exactly as one against a reference that
    # was never referenced by a send at all.
    for reference in (sent_reference, unsent_reference):
        verified = pin.verify_otp_message(
            ApplicationId=app_id,
            VerifyOTPMessageRequestParameters={
                "DestinationIdentity": destination,
                "Otp": "000000",
                "ReferenceId": reference,
            },
        )["VerificationResponse"]
        assert verified == {"Valid": False}, (
            f"expected {{'Valid': False}} for reference {reference!r}, got {verified!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
