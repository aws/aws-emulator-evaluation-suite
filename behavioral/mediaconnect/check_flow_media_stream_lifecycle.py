"""flow-media-stream-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "flow-media-stream-lifecycle"
GROUP = "data-plane"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddFlowMediaStreams adds an audio stream DescribeFlow shows with description 'initial',
    UpdateFlowMediaStream changes it to 'updated', RemoveFlowMediaStream removes it, and a further update
    fails NotFoundException 'Not found: audio-1'."""
    mc = ctx.client("mediaconnect")
    flow_arn = mc.create_flow(
        Name=ctx.unique_name("sim2real-mc-flow-"),
        Source={"Name": "source1", "Protocol": "rtp", "WhitelistCidr": "203.0.113.0/24"},
        FlowTags={"sim2real:managed": "true", "sim2real": CHECK},
    )["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: mc.delete_flow(FlowArn=flow_arn))

    mc.add_flow_media_streams(
        FlowArn=flow_arn,
        MediaStreams=[
            {
                "MediaStreamId": 1,
                "MediaStreamName": "audio-1",
                "MediaStreamType": "audio",
                "ClockRate": 48000,
                "Description": "initial",
                "Attributes": {"Fmtp": {"ChannelOrder": "SMPTE2110.(ST)"}, "Lang": "eng"},
            }
        ],
    )

    streams = mc.describe_flow(FlowArn=flow_arn)["Flow"]["MediaStreams"]
    match = next((s for s in streams if s["MediaStreamName"] == "audio-1"), None)
    assert match is not None, f"audio-1 missing from MediaStreams after AddFlowMediaStreams: {streams!r}"
    assert match.get("Description") == "initial", (
        f"expected Description='initial' after AddFlowMediaStreams, got {match.get('Description')!r}"
    )

    mc.update_flow_media_stream(
        FlowArn=flow_arn, MediaStreamName="audio-1", Description="updated"
    )
    streams = mc.describe_flow(FlowArn=flow_arn)["Flow"]["MediaStreams"]
    match = next((s for s in streams if s["MediaStreamName"] == "audio-1"), None)
    assert match is not None, f"audio-1 disappeared from MediaStreams after UpdateFlowMediaStream: {streams!r}"
    assert match.get("Description") == "updated", (
        f"expected Description='updated' after UpdateFlowMediaStream, got {match.get('Description')!r}"
    )

    mc.remove_flow_media_stream(FlowArn=flow_arn, MediaStreamName="audio-1")
    streams = mc.describe_flow(FlowArn=flow_arn)["Flow"]["MediaStreams"]
    assert not any(s["MediaStreamName"] == "audio-1" for s in streams), (
        f"audio-1 still present after RemoveFlowMediaStream: {streams!r}"
    )

    code, message = _client_error(
        lambda: mc.update_flow_media_stream(FlowArn=flow_arn, MediaStreamName="audio-1", Description="ghost")
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException updating a removed media stream, got {code!r}"
    )
    assert message == "Not found: audio-1", (
        f"expected message 'Not found: audio-1' updating a removed media stream, got {message!r}"
    )


def _client_error(fn):
    try:
        fn()
    except Exception as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call against the removed media stream to fail, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
