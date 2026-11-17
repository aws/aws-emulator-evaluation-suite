"""list-graphql-apis-max-results-above-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-graphql-apis-max-results-above-limit-rejected"
GROUP = 'graphql-api'
SERVICES = ['appsync']

_ABOVE_LIMIT = (
    "BadRequestException",
    "maxResults must be greater than 0 and less than or equal to 25.",
)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected error code {code!r}, got {got_code!r}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListGraphqlApis refuses a maxResults above 25 with its exact message, while the
    documented ceiling of 25 itself still succeeds.
    """
    svc = ctx.client("appsync")

    expect_error(lambda: svc.list_graphql_apis(maxResults=26), *_ABOVE_LIMIT)

    at_ceiling = svc.list_graphql_apis(maxResults=25)
    assert "graphqlApis" in at_ceiling, f"maxResults=25 should succeed, got {at_ceiling!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
