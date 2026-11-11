"""create-channel-duplicate-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-duplicate-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackage"]


def _error_code(fn):
    """The AWS (code, message) for a call that MUST fail.

    A call that unexpectedly SUCCEEDS raises rather than returning a falsy sentinel.
    """
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"the call was expected to be refused as a duplicate Id but it SUCCEEDED: {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChannel with an Id that already exists is rejected with
    UnprocessableEntityException, the original channel is left untouched, and a
    fresh Id still succeeds (positive control)."""
    mp = ctx.client("mediapackage")

    cid = ctx.unique_name("sim2real-mp-dup-")
    mp.create_channel(Id=cid, Description="first", Tags={"purpose": "behavioral-check"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=cid))

    code, message = _error_code(lambda: mp.create_channel(Id=cid, Description="second"))
    assert code == "UnprocessableEntityException", (
        f"CreateChannel with a duplicate Id was rejected with {code!r}, expected "
        f"'UnprocessableEntityException'"
    )
    expected_message = f"channel with id={cid} already exists"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the original channel's Description was not overwritten
    described = mp.describe_channel(Id=cid)
    assert described["Description"] == "first", (
        f"the rejected duplicate create still overwrote Description: expected 'first', got "
        f"{described['Description']!r}"
    )

    # positive control: a distinct Id succeeds, verified via an independent read (not the
    # CreateChannel response itself)
    cid2 = ctx.unique_name("sim2real-mp-dup2-")
    mp.create_channel(Id=cid2, Tags={"purpose": "behavioral-check"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=cid2))
    described2 = mp.describe_channel(Id=cid2)
    assert described2["Id"] == cid2, (
        f"a fresh Id after the rejection did not persist: describe_channel returned "
        f"{described2['Id']!r}, expected {cid2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
