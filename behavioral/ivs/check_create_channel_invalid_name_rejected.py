"""create-channel-invalid-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-invalid-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel and ListChannels' filterByName both refuse a name outside ^[a-zA-Z0-9-_]*$ with
    ValidationException and the exact message, while a valid name creates the channel."""
    ivs = ctx.client("ivs")
    bad_name = ctx.unique_name("sim2real ivs chan!! ")

    error = _client_error(lambda: ivs.create_channel(name=bad_name))
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error["Message"] == (
        "CreateChannel.name does not match the required pattern ^[a-zA-Z0-9-_]*$"
    ), f"unexpected CreateChannel validation message: {error['Message']!r}"

    # the same invalid name is rejected by the read path too -- there is no way such a channel
    # could ever have been persisted under this name
    error_list = _client_error(lambda: ivs.list_channels(filterByName=bad_name))
    assert error_list["Code"] == "ValidationException", (
        f"expected ListChannels(filterByName=<invalid>) to also reject with "
        f"ValidationException, got {error_list!r}"
    )
    assert error_list["Message"] == (
        "ListChannels.filterByName does not match the required pattern ^[a-zA-Z0-9-_]*$"
    ), f"unexpected ListChannels validation message: {error_list['Message']!r}"

    good_name = ctx.unique_name("sim2real-ivs-chan-")
    good_arn = ivs.create_channel(name=good_name)["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=good_arn))
    got_name = ivs.get_channel(arn=good_arn)["channel"]["name"]
    assert got_name == good_name, f"expected channel name {good_name!r}, got {got_name!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
