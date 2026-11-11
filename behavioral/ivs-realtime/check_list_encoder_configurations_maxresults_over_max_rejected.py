"""list-encoder-configurations-maxresults-over-max-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-encoder-configurations-maxresults-over-max-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListEncoderConfigurations rejects maxResults above the documented 100 maximum,
    while 100 itself succeeds."""
    ivsrt = ctx.client("ivs-realtime")

    ok = ivsrt.list_encoder_configurations(maxResults=100)
    assert "encoderConfigurations" in ok, f"expected an encoderConfigurations key, got {ok!r}"

    code, message = _error(lambda: ivsrt.list_encoder_configurations(maxResults=101))
    assert code == "ValidationException", f"expected ValidationException for maxResults=101, got {code}"
    expected_message = (
        "ListEncoderConfigurations.maxResults is required to have a maximum value of 100.0, found 101.0"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects maxResults=101, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
