"""encoder-configuration-pixel-product-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "encoder-configuration-pixel-product-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEncoderConfiguration at 1920x1920 exceeds the 2,073,600-pixel budget and fails ValidationException
    with the exact message, leaving nothing listed, while 1920x1080 succeeds and reads back."""
    client = ctx.client("ivs-realtime")
    bad_name = ctx.unique_name("sim2real-encoder-toobig")

    code, message = _error(
        lambda: client.create_encoder_configuration(
            name=bad_name, video={"width": 1920, "height": 1920}
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for 1920x1920 (3,686,400px > 2,073,600 budget), got {code!r}"
    )
    expected_message = (
        "Request member: video failed to satisfy the constraints: "
        "Code: VideoResolutionLimitError Message: video resolution exceeded max limit"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect absent: no encoder configuration with that name exists anywhere in the list.
    names = {e["name"] for e in _list_all(client)}
    assert bad_name not in names, f"rejected create {bad_name!r} is still visible in list_encoder_configurations"

    # Positive control: the maximum in-budget resolution (1920x1080 = 2,073,600px) works.
    ok_name = ctx.unique_name("sim2real-encoder-ok")
    created = client.create_encoder_configuration(
        name=ok_name, video={"width": 1920, "height": 1080}, tags={"sim2real": "audit"}
    )["encoderConfiguration"]
    ctx.on_cleanup(lambda: client.delete_encoder_configuration(arn=created["arn"]))

    # Terminal read is independent of the mutating call: GetEncoderConfiguration, not
    # CreateEncoderConfiguration's own response.
    fetched = client.get_encoder_configuration(arn=created["arn"])["encoderConfiguration"]
    assert fetched["video"]["width"] == 1920, f"expected width 1920, got {fetched['video']['width']!r}"
    assert fetched["video"]["height"] == 1080, f"expected height 1080, got {fetched['video']['height']!r}"


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


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected ValidationException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
