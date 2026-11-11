"""create-origin-endpoint-missing-channel-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-origin-endpoint-missing-channel-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackage"]


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOriginEndpoint against a ChannelId that does not exist is rejected with
    UnprocessableEntityException, no endpoint is persisted, and the same Id succeeds once a real
    channel is used (positive control)."""
    mp = ctx.client("mediapackage")

    bogus_channel = ctx.unique_name("sim2real-mp-nochan-")
    oid = ctx.unique_name("sim2real-mp-oe-")

    code, message = _error_code(
        lambda: mp.create_origin_endpoint(Id=oid, ChannelId=bogus_channel, HlsPackage={})
    )
    assert code == "UnprocessableEntityException", f"unexpected error code: {code!r}"
    assert message == "channelId not found", f"expected message 'channelId not found', got {message!r}"

    # effect absent: no origin endpoint was persisted under this Id
    absent_code, absent_message = _error_code(lambda: mp.describe_origin_endpoint(Id=oid))
    assert absent_code == "NotFoundException", f"expected NotFoundException, got {absent_code!r}"
    expected_absent = f"originEndpoint with id={oid} not found"
    assert absent_message == expected_absent, (
        f"expected message {expected_absent!r}, got {absent_message!r}"
    )

    # positive control: a real channel accepts the same origin endpoint Id
    real_channel = ctx.unique_name("sim2real-mp-chan-")
    mp.create_channel(Id=real_channel, Tags={"created-by": "sim2real"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=real_channel))

    created = mp.create_origin_endpoint(
        Id=oid, ChannelId=real_channel, HlsPackage={}, Tags={"created-by": "sim2real"}
    )
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=oid))
    assert created["Id"] == oid

    # terminal assertion is an independent read, not the mutating call's own response
    described = mp.describe_origin_endpoint(Id=oid)
    assert described["ChannelId"] == real_channel


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
