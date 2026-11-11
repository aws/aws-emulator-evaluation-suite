"""get-graphql-api-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected GetGraphqlApi to raise NotFoundException, but it SUCCEEDED and returned {result!r}"
    )

CHECK = "get-graphql-api-not-found"
GROUP = 'graphql-api'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetGraphqlApi on an id that was never created raises NotFoundException (not a generic
    error), while the identical call for a real, just-created api succeeds -- proving the
    negative is a genuine not-found and not a target that rejects every GetGraphqlApi call."""
    svc = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-appsync-api-")
    api = svc.create_graphql_api(
        name=name, authenticationType="API_KEY", tags={"sim2real": "behav"}
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))

    # Positive control: the account and credentials can create and read a real GraphQL API.
    got = svc.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert got["apiId"] == api_id, f"expected apiId {api_id!r}, got {got.get('apiId')!r}"

    bogus_id = "nonexistent-" + ctx.unique_name("sim2real-behav-api-")
    code, message = _error(lambda: svc.get_graphql_api(apiId=bogus_id))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "API not found.", f"unexpected NotFoundException message {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
