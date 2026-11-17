"""create-api-key-description-length-boundary."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-api-key-description-length-boundary"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApiKey accepts a 256-character description and rejects 257 with a BadRequestException
    naming the 256-character bound; ListApiKeys then shows only the accepted key.
    """
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda _a=api_id: svc.delete_graphql_api(apiId=_a))

    at_limit = "d" * 256
    accepted = svc.create_api_key(apiId=api_id, description=at_limit)["apiKey"]
    accepted_id = accepted["id"]
    ctx.on_cleanup(lambda _a=api_id, _k=accepted_id: svc.delete_api_key(apiId=_a, id=_k))
    assert accepted["description"] == at_limit, (
        f"expected the 256-character description to be accepted verbatim, got {accepted['description']!r}"
    )

    over_limit = "d" * 257
    code, message = _error(lambda: svc.create_api_key(apiId=api_id, description=over_limit))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Invalid description given, must be less than 256 characters.", (
        f"unexpected message: {message!r}"
    )

    listed_ids = [k["id"] for k in svc.list_api_keys(apiId=api_id)["apiKeys"]]
    assert listed_ids == [accepted_id], (
        f"expected only the accepted key to exist, got {listed_ids!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
