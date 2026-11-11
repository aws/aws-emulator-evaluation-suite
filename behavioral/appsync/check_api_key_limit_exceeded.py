"""api-key-limit-exceeded."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-key-limit-exceeded"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApiKey past the per-API key limit fails with ApiKeyLimitExceededException; the failed
    call creates nothing, and freeing one slot lets an identical call succeed again."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": "behavioral"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]

    def _delete_key_if_present(key_id):
        try:
            svc.delete_api_key(apiId=api_id, id=key_id)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "NotFoundException":
                raise

    def _list_key_ids():
        ids, next_token = set(), None
        while True:
            kwargs = {"apiId": api_id, **({"nextToken": next_token} if next_token else {})}
            resp = svc.list_api_keys(**kwargs)
            ids.update(k["id"] for k in resp["apiKeys"])
            next_token = resp.get("nextToken")
            if not next_token:
                return ids

    limit_code = None
    limit_message = None
    created_ids = []
    for i in range(55):
        try:
            key = svc.create_api_key(apiId=api_id, description=f"sim2real key {i}")["apiKey"]
        except ClientError as exc:
            limit_code = exc.response.get("Error", {}).get("Code")
            limit_message = exc.response.get("Error", {}).get("Message")
            break
        else:
            ctx.on_cleanup(lambda _k=key["id"]: _delete_key_if_present(_k))
            created_ids.append(key["id"])

    created = len(created_ids)
    assert limit_code == "ApiKeyLimitExceededException", (
        f"expected ApiKeyLimitExceededException once the per-API ApiKey ceiling is "
        f"reached (created {created} keys before this point), got {limit_code}"
    )
    # The ceiling AWS names in its message is the number of keys this fresh API held when the
    # create was refused.
    assert limit_message == f"API key limit ({created}) exceeded.", (
        f"expected AWS's exact ceiling message naming the {created}-key limit, got {limit_message!r}"
    )

    listed_ids = _list_key_ids()
    assert listed_ids == set(created_ids), (
        f"the rejected CreateApiKey must create nothing: expected exactly the {created} "
        f"successfully-created keys to be listed, got {len(listed_ids)} "
        f"(diff: {listed_ids ^ set(created_ids)})"
    )

    freed_id = created_ids.pop()
    _delete_key_if_present(freed_id)
    retry_key = svc.create_api_key(apiId=api_id, description="sim2real key retry")["apiKey"]
    ctx.on_cleanup(lambda _k=retry_key["id"]: _delete_key_if_present(_k))
    created_ids.append(retry_key["id"])

    listed_after_restore = _list_key_ids()
    assert freed_id not in listed_after_restore, (
        f"deleted key {freed_id} is still listed after the restore leg"
    )
    assert retry_key["id"] in listed_after_restore, (
        f"freeing one slot below the ceiling must let an identical CreateApiKey succeed again "
        f"and become visible at {retry_key['id']!r}, proving the earlier rejection was the real "
        f"per-API boundary and not a blanket failure"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
