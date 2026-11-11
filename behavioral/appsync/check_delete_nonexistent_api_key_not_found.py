"""delete-nonexistent-api-key-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

CHECK = "delete-nonexistent-api-key-not-found"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteApiKey for an id already deleted fails NotFoundException rather than a silent no-op, and
    an independent ListApiKeys read confirms the key is gone."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]

    key = svc.create_api_key(apiId=api_id, description="deleted-twice")["apiKey"]
    key_id = key["id"]

    before = svc.list_api_keys(apiId=api_id)["apiKeys"]
    assert any(k["id"] == key_id for k in before), "created ApiKey did not appear in ListApiKeys"

    svc.delete_api_key(apiId=api_id, id=key_id)

    after = svc.list_api_keys(apiId=api_id)["apiKeys"]
    assert not any(k["id"] == key_id for k in after), (
        "deleted ApiKey still present in an independent ListApiKeys read"
    )

    err = _error(lambda: svc.delete_api_key(apiId=api_id, id=key_id))
    assert err == ("NotFoundException", f"API key not found: {key_id}"), (
        f"expected NotFoundException deleting an ApiKey id that no longer exists, got {err}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
