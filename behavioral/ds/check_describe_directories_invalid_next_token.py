"""describe-directories-invalid-next-token."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message, RequestId) of the ClientError. An
    unexpected SUCCESS raises, because an emulator ACCEPTING a token real AWS refuses is the strongest
    signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = exc.response.get("ResponseMetadata", {}).get("RequestId")
        return err.get("Code"), err.get("Message"), request_id
    raise AssertionError(
        f"expected InvalidNextTokenException, but the call SUCCEEDED and returned {result!r}"
    )


CHECK = "describe-directories-invalid-next-token"
GROUP = 'error-semantics'
SERVICES = ['ds']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A NextToken not minted by ds is rejected with InvalidNextTokenException, while the
    same unfiltered call with no token succeeds (positive control) — so the rejection is
    specific to the bogus cursor, not ds refusing every DescribeDirectories call."""
    ds = ctx.client("ds")

    control = ds.describe_directories()
    assert isinstance(control.get("DirectoryDescriptions"), list), (
        f"unfiltered DescribeDirectories must return a DirectoryDescriptions list: {control}"
    )

    code, message, rid = _error(
        lambda: ds.describe_directories(NextToken="sim2real-bogus-pagination-token")
    )
    assert code == "InvalidNextTokenException", f"unexpected code: {code}"
    expected_message = f"Invalid value passed for the NextToken parameter. : RequestId: {rid}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
