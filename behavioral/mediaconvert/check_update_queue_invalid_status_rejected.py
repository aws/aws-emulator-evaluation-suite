"""update-queue-invalid-status-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-queue-invalid-status-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediaconvert"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateQueue with a Status value outside the ACTIVE/PAUSED enum must be rejected, and the
    queue's Status must be unchanged. A valid Status value, by contrast, is accepted and
    persists (the positive control)."""
    mc = ctx.client("mediaconvert")
    name = ctx.unique_name("sim2real-mc-queue-")
    mc.create_queue(Name=name, Tags={"sim2real-check": "true"})
    ctx.on_cleanup(lambda: mc.delete_queue(Name=name))

    code, message = _error(lambda: mc.update_queue(Name=name, Status="BOGUS_STATUS"))
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected = (
        "You specified an invalid type for 'status'. Replace the value with a QueueStatus (Valid "
        "values: 'ACTIVE', 'PAUSED'), or remove 'status' (if optional), then resubmit your request. "
        "For more information, see the MediaConvert API reference: "
        "https://docs.aws.amazon.com/mediaconvert/latest/apireference/resources.html"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    got = mc.get_queue(Name=name)["Queue"]
    assert got["Status"] == "ACTIVE", f"expected Status unchanged at ACTIVE, got {got['Status']!r}"

    # positive control: a valid Status value is accepted and persists
    mc.update_queue(Name=name, Status="PAUSED")
    got2 = mc.get_queue(Name=name)["Queue"]
    assert got2["Status"] == "PAUSED", f"expected Status PAUSED after valid update, got {got2['Status']!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
