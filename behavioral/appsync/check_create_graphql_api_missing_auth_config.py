"""create-graphql-api-missing-auth-config."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its (error code, message, HTTP status).
    An unexpected success raises: accepting what AWS refuses is a finding, not a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), err.get("Message") or "", status
    raise AssertionError(f"expected CreateGraphqlApi to be rejected, but it SUCCEEDED: {result!r}")

CHECK = "create-graphql-api-missing-auth-config"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGraphqlApi with AMAZON_COGNITO_USER_POOLS auth and no userPoolConfig fails
    BadRequestException and registers no API under its name; a well-formed request succeeds."""
    svc = ctx.client("appsync")

    good_name = ctx.unique_name("sim2real-behav-appsync-api-ok-")
    created = svc.create_graphql_api(name=good_name, authenticationType="API_KEY")["graphqlApi"]
    api_id = created["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))

    fetched = svc.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert fetched["name"] == good_name, (
        f"positive control: expected GetGraphqlApi to see {good_name!r}, got {fetched['name']!r}"
    )

    bad_name = ctx.unique_name("sim2real-behav-appsync-api-badauth-")

    def attempt():
        return svc.create_graphql_api(name=bad_name, authenticationType="AMAZON_COGNITO_USER_POOLS")

    code, message, status = _error(attempt)
    assert (code, status) == ("BadRequestException", 400), (
        f"expected BadRequestException/400, got {code!r}/{status!r}"
    )
    expected_message = "User Pool Config is empty"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    listed, kwargs = [], {}
    while True:
        page = svc.list_graphql_apis(**kwargs)
        listed.extend(page["graphqlApis"])
        if not page.get("nextToken"):
            break
        kwargs = {"nextToken": page["nextToken"]}
    assert not any(a["name"] == bad_name for a in listed), (
        f"rejected CreateGraphqlApi call for {bad_name!r} must not register an API, "
        f"but ListGraphqlApis shows it"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
