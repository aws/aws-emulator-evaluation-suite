"""lookup-events-invalid-next-token-fails."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError was raised. An
    unexpected SUCCESS raises, because an emulator ACCEPTING a token it never minted is the strongest
    signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"real AWS rejects a NextToken it never minted, but the call SUCCEEDED and "
        f"returned {result!r}"
    )


CHECK = "lookup-events-invalid-next-token-fails"
GROUP = 'error-semantics'
SERVICES = ['cloudtrail']

@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """LookupEvents rejects an opaque pagination token it did not mint, while an ordinary
    unpaginated call still succeeds -- the positive control that separates "rejects this
    token" from "rejects everything"."""
    ct = ctx.client("cloudtrail")

    # Positive control: CloudTrail is reachable and LookupEvents itself works.
    control = ct.lookup_events()
    assert control["ResponseMetadata"]["HTTPStatusCode"] == 200, control["ResponseMetadata"]
    assert isinstance(control.get("Events"), list), control

    code, message = _error(
        lambda: ct.lookup_events(NextToken="sim2real-behav-not-a-real-token")
    )
    assert code == "InvalidNextTokenException", (
        f"expected InvalidNextTokenException for a NextToken cloudtrail never minted, "
        f"got {code!r}"
    )
    assert message == "Can't decrypt marker", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
