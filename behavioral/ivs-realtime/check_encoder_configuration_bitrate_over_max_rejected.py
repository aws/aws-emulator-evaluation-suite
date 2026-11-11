"""encoder-configuration-bitrate-over-max-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "encoder-configuration-bitrate-over-max-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEncoderConfiguration rejects bitrate above the 8,500,000 bps maximum, while
    the boundary value itself succeeds, and the rejected attempt leaves no encoder
    configuration behind."""
    ivsrt = ctx.client("ivs-realtime")

    ok = ivsrt.create_encoder_configuration(
        name=ctx.unique_name("sim2real-ivsrt-enc-"),
        video={"width": 1280, "height": 720, "framerate": 30, "bitrate": 8500000},
        tags={"sim2real-check": "encoder-configuration-bitrate-over-max-rejected"},
    )["encoderConfiguration"]
    ctx.on_cleanup(lambda: ivsrt.delete_encoder_configuration(arn=ok["arn"]))
    assert ok["video"]["bitrate"] == 8500000, f"boundary bitrate 8500000 was not preserved: {ok['video']!r}"

    bad_name = ctx.unique_name("sim2real-ivsrt-enc-")
    _reject(
        lambda: ivsrt.create_encoder_configuration(
            name=bad_name,
            video={"width": 1280, "height": 720, "framerate": 30, "bitrate": 8500001},
        )
    )

    # Effect absent: the rejected attempt did not leave a partially-created resource.
    names = {e["name"] for e in _list_all(ivsrt)}
    assert bad_name not in names, (
        f"a bitrate of 8500001 was rejected, but {bad_name!r} is visible in "
        f"list_encoder_configurations anyway: {names!r}"
    )


def _reject(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ValidationException", (
            f"expected ValidationException for a bitrate of 8,500,001 bps, got {code!r}"
        )
        return
    raise AssertionError(
        f"real AWS rejects a bitrate of 8,500,001 bps, but the call SUCCEEDED and returned "
        f"{result!r}"
    )


def _list_all(client):
    items = []
    next_token = None
    while True:
        params = {"nextToken": next_token} if next_token else {}
        resp = client.list_encoder_configurations(**params)
        items.extend(resp["encoderConfigurations"])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
