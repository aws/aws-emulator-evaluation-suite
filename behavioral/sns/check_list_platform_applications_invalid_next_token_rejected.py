"""list-platform-applications-invalid-next-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-platform-applications-invalid-next-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["sns"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListPlatformApplications with a malformed pagination token is rejected with
    InvalidParameter instead of returning an arbitrary page; an ordinary (token-less)
    call for the same account still succeeds, both before and after the bad call."""
    sns = ctx.client("sns")

    # Positive control: an ordinary (token-less) list call succeeds, whatever it returns.
    resp = sns.list_platform_applications()
    assert "PlatformApplications" in resp, (
        f"expected a PlatformApplications key in the response, got keys {sorted(resp)}"
    )

    # Break exactly one thing: a NextToken that could never have been issued by SNS.
    code, message = _error(lambda: sns.list_platform_applications(NextToken="not-a-real-token=="))
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for a NextToken that was never issued, got {code!r}"
    )
    expected = 'Invalid parameter: NextToken Reason: token is invalid or expired'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent / no corruption: an ordinary list call still works afterwards.
    resp = sns.list_platform_applications()
    assert "PlatformApplications" in resp, (
        "expected a PlatformApplications key in the response after the rejected call, "
        f"got keys {sorted(resp)}"
    )


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects a NextToken it never issued, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

