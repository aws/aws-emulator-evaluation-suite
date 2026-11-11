"""create-get-delete-graphql-api."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the (code, message, HTTP status) of the ClientError it raises. An
    unexpected success raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), err.get("Message") or "", status
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _delete_if_present(fn):
    """Teardown for a resource the check may already have deleted itself."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise

def _list_api_ids(svc):
    """Every GraphqlApi id in the region, following nextToken."""
    ids, kwargs = [], {}
    while True:
        page = svc.list_graphql_apis(**kwargs)
        ids.extend(a["apiId"] for a in page["graphqlApis"])
        if not page.get("nextToken"):
            return ids
        kwargs = {"nextToken": page["nextToken"]}

CHECK = "create-get-delete-graphql-api"
GROUP = 'graphql-api'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGraphqlApi -> Get -> Update applied -> List -> Delete -> gone: not-found by id,
    absent from the listing, and refused for update and key creation."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: _delete_if_present(lambda: svc.delete_graphql_api(apiId=_a["apiId"])))
    api_id = api["apiId"]

    got = svc.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert got["apiId"] == api_id, f"expected apiId {api_id!r}, got {got['apiId']!r}"
    assert got["name"] == api["name"], f"expected name {api['name']!r}, got {got['name']!r}"
    assert got["authenticationType"] == "API_KEY", (
        f"expected authenticationType API_KEY, got {got['authenticationType']!r}"
    )
    want_arn = f"arn:aws:appsync:{ctx.region}:{ctx.account}:apis/{api_id}"
    assert got.get("arn") == want_arn, f"expected arn {want_arn!r}, got {got.get('arn')!r}"

    new_name = ctx.unique_name("sim2real-behav-appsync-api-upd-")
    svc.update_graphql_api(apiId=api_id, name=new_name, authenticationType="API_KEY")
    got = svc.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert got["name"] == new_name, f"expected the updated name {new_name!r}, got {got['name']!r}"

    ids = _list_api_ids(svc)
    assert api_id in ids, f"expected the api in ListGraphqlApis, got {len(ids)} apis without it"

    svc.delete_graphql_api(apiId=api_id)

    code, message, status = _error(lambda: svc.get_graphql_api(apiId=api_id))
    assert code == "NotFoundException" and isinstance(status, int) and 400 <= status < 500, (
        f"expected GetGraphqlApi after delete to be NotFoundException/4xx, got {code!r}/{status!r}"
    )
    expected_message = "API not found."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    ids = _list_api_ids(svc)
    assert api_id not in ids, "expected the deleted api to be absent from ListGraphqlApis"

    for label, call in (
        ("UpdateGraphqlApi", lambda: svc.update_graphql_api(apiId=api_id, name=new_name, authenticationType="API_KEY")),
        ("CreateApiKey", lambda: svc.create_api_key(apiId=api_id)),
    ):
        code, message, status = _error(call)
        assert code == "NotFoundException" and isinstance(status, int) and 400 <= status < 500, (
            f"expected {label} on the deleted api to be NotFoundException/4xx, got {code!r}/{status!r}"
        )
        expected_message = "API not found."
        assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
