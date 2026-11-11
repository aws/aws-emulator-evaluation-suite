"""rotate-channel-credentials-nonexistent-channel-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "rotate-channel-credentials-nonexistent-channel-not-found"
GROUP = "overly-permissive"
SERVICES = ["mediapackage"]


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING an Id real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected NotFoundException, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RotateChannelCredentials on an Id that names no channel fails NotFoundException with the exact
    message, while on a real channel it changes the ingest credentials and DescribeChannel returns the
    rotated ones."""
    mp = ctx.client("mediapackage")

    bogus_id = ctx.unique_name("sim2real-mp-missing-")
    code, message = _error_code(lambda: mp.rotate_channel_credentials(Id=bogus_id))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == f"channel with id={bogus_id} not found", (
        f"expected the exact NotFoundException message AWS returns, got {message!r}"
    )

    real_id = ctx.unique_name("sim2real-mp-real-")
    created = mp.create_channel(Id=real_id, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=real_id))
    before = created["HlsIngest"]["IngestEndpoints"][0]

    rotated = mp.rotate_channel_credentials(Id=real_id)
    after = rotated["HlsIngest"]["IngestEndpoints"][0]
    assert after["Username"] != before["Username"] or after["Password"] != before["Password"], (
        f"RotateChannelCredentials did not change credentials: before={before!r} after={after!r}"
    )

    described = mp.describe_channel(Id=real_id)
    described_ep = described["HlsIngest"]["IngestEndpoints"][0]
    assert described_ep["Username"] == after["Username"], (
        f"DescribeChannel does not reflect the rotated username: "
        f"describe={described_ep['Username']!r} rotate_response={after['Username']!r}"
    )
    assert described_ep["Password"] == after["Password"], (
        f"DescribeChannel does not reflect the rotated password: "
        f"describe={described_ep['Password']!r} rotate_response={after['Password']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
