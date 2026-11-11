"""list-resource-requests-invalid-next-token-rejected."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "list-resource-requests-invalid-next-token-rejected"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A syntactically valid but non-existent NextToken is rejected, not silently treated as page 1."""
    cc = ctx.client("cloudcontrol")

    # Positive control: an unfiltered, un-paginated call succeeds and returns a real page.
    control = cc.list_resource_requests(MaxResults=5)
    assert "ResourceRequestStatusSummaries" in control, (
        f"expected ResourceRequestStatusSummaries in a healthy ListResourceRequests response, got {control!r}"
    )

    # Bogus token: matches the NextToken charset ([-A-Za-z0-9+/=]+) so it isn't rejected by
    # client-side shape validation, but was never issued by the service.
    bogus_token = "A" * 64
    code, message = _error(lambda: cc.list_resource_requests(MaxResults=5, NextToken=bogus_token))
    assert code == "ValidationException", (
        f"expected a validation-style rejection for a bogus NextToken, got {code!r}"
    )
    assert message == "Invalid NextToken", f"expected 'Invalid NextToken', got {message!r}"

    # The rejection must not have silently substituted a valid page: repeating the same
    # positive-control call still succeeds and is unaffected by the bogus request.
    control_again = cc.list_resource_requests(MaxResults=5)
    assert "ResourceRequestStatusSummaries" in control_again, (
        f"expected the identical positive-control call to keep succeeding after the bogus "
        f"NextToken was rejected, got {control_again!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a bogus NextToken real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects a bogus NextToken, but ListResourceRequests SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
