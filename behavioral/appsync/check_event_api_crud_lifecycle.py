"""event-api-crud-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn() and return its botocore error (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")

CHECK = "event-api-crud-lifecycle"
GROUP = 'event-api'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Event Api resource: CreateApi -> GetApi -> ListApis -> UpdateApi -> DeleteApi -> GetApi 404, and removed from ListApis."""
    svc = ctx.client("appsync")
    # authProviders includes both API_KEY and AWS_IAM so channel/connection auth
    # modes can legitimately reference either; connection/publish/subscribe modes
    # must be a subset of the API's configured authProviders.
    default_auth = [{"authType": "API_KEY"}]
    all_auth = [{"authType": "API_KEY"}, {"authType": "AWS_IAM"}]
    api = svc.create_api(
        name=ctx.unique_name("sim2real-behav-appsync-eventapi-"),
        eventConfig={
            "authProviders": all_auth,
            "connectionAuthModes": default_auth,
            "defaultPublishAuthModes": default_auth,
            "defaultSubscribeAuthModes": default_auth,
        },
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav-appsync-eventapi"},
    )["api"]
    ctx.on_cleanup(lambda _a=api: _delete_api_quiet(svc, _a["apiId"]))
    api_id = api["apiId"]
    assert api.get("apiArn"), "CreateApi must return an apiArn"

    got = svc.get_api(apiId=api_id)["api"]
    assert got["apiId"] == api_id
    assert got["name"] == api["name"]

    ids = _list_api_ids(svc)
    assert api_id in ids, "newly created Event API must appear in ListApis"

    new_name = ctx.unique_name("sim2real-behav-evt-renamed-")
    # Real AppSync's UpdateApi requires eventConfig on the wire even though it's
    # semantically optional (unchanged) — round-trip the existing config.
    svc.update_api(apiId=api_id, name=new_name, eventConfig=got["eventConfig"])
    updated = svc.get_api(apiId=api_id)["api"]
    assert updated["name"] == new_name, f"expected updated name {new_name!r}, got {updated['name']!r}"

    svc.delete_api(apiId=api_id)

    code, message = _error(lambda: svc.get_api(apiId=api_id))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code}"
    assert message == "API not found.", f"unexpected GetApi message after delete: {message!r}"

    ids_after = _list_api_ids(svc)
    assert api_id not in ids_after, "deleted Event API must disappear from ListApis"

    # A mutation on the dead id must also fail, not just a read -- otherwise a
    # target that only stops serving reads (while still accepting writes on a
    # "deleted" id) would pass GetApi's 404 and nothing else would catch it.
    mutate_code, mutate_message = _error(
        lambda: svc.update_api(apiId=api_id, name=new_name, eventConfig=updated["eventConfig"])
    )
    assert mutate_code == "NotFoundException", (
        f"expected NotFoundException on UpdateApi against a deleted apiId, got {mutate_code}"
    )
    assert mutate_message == "API not found.", (
        f"unexpected UpdateApi message against a deleted apiId: {mutate_message!r}"
    )


#: Upper bound on the pages one listing walk follows.
_MAX_PAGES = 500


def _list_api_ids(svc) -> set:
    """Every apiId ListApis returns, across all pages."""
    ids, token = set(), None
    for _ in range(_MAX_PAGES):
        page = svc.list_apis(**({"nextToken": token} if token else {}))
        ids.update(a["apiId"] for a in page.get("apis", []))
        token = page.get("nextToken")
        if not token:
            return ids
    raise AssertionError(f"ListApis still returned a nextToken after {_MAX_PAGES} pages")


def _delete_api_quiet(svc, api_id: str) -> None:
    """Teardown for an Api the check itself deletes: an already-deleted Api is fine."""
    try:
        svc.delete_api(apiId=api_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
