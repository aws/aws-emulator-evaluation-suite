"""create-stream-group-invalid-stream-class-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stream-group-invalid-stream-class-rejected"
GROUP = "validation"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStreamGroup rejects a StreamClass value outside the documented enum with ValidationException,
    while a valid StreamClass still succeeds and is visible on an independent GetStreamGroup read."""
    gls = ctx.client("gameliftstreams")

    code, message = _error_code(
        lambda: gls.create_stream_group(
            Description=ctx.unique_name("sim2real-behav-gls-sg-"),
            StreamClass="not_a_real_stream_class",
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for an out-of-enum StreamClass, got {code!r}"
    )
    expected = (
        "1 validation error detected: Value 'not_a_real_stream_class' at 'streamClass' failed to "
        "satisfy constraint: Member must satisfy enum value set: [gen4n_high, gen4n_ultra, "
        "gen4n_win2022, gen5n_high, gen5n_ultra, gen5n_win2022, gen6n_small, gen6n_medium, "
        "gen6n_high, gen6n_ultra, gen6n_ultra_win2022, gen6n_pro, gen6n_pro_win2022, gen6e_pro, "
        "gen6e_pro_win2022]"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # positive control: a real stream class value succeeds
    try:
        group = gls.create_stream_group(
            Description=ctx.unique_name("sim2real-behav-gls-sg-"), StreamClass="gen6n_small"
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServiceQuotaExceededException":
            raise AssertionError(
                f"account has no GPU quota in this Region ({e}); GameLift Streams GPU quotas "
                "default to 0 and must be explicitly requested"
            )
        raise
    arn = group["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: gls.delete_stream_group(Identifier=arn)))
    assert group["StreamClass"] == "gen6n_small", (
        f"CreateStreamGroup's own response reported StreamClass {group['StreamClass']!r}, "
        "expected 'gen6n_small'"
    )

    # independent read at the destination: GetStreamGroup, not the mutating call's own response
    reread = gls.get_stream_group(Identifier=arn)
    assert reread["StreamClass"] == "gen6n_small", (
        f"GetStreamGroup reports StreamClass {reread['StreamClass']!r} for a group created with "
        "'gen6n_small'"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected CreateStreamGroup to reject the invalid StreamClass, but it SUCCEEDED and "
        f"returned {result!r}"
    )


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
