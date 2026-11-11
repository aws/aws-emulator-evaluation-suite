"""channel-namespace-list-ordering."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore error (code, message); an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _ns_name(raw):
    """Channel-namespace name: ([A-Za-z0-9](?:[A-Za-z0-9-]{0,48}[A-Za-z0-9])?), <=50 chars."""
    cleaned = re.sub(r"[^0-9A-Za-z-]", "-", raw)
    cleaned = re.sub(r"-+", "-", cleaned).strip("-")
    if len(cleaned) > 50:
        cleaned = cleaned[:50]
    cleaned = cleaned.strip("-")
    if not cleaned or not cleaned[0].isalnum():
        cleaned = "n" + cleaned
    return cleaned

def _list_all(call, items_key, **params):
    """Paginate any AppSync ``List*`` call (all use ``nextToken``) and return the concatenated items."""
    results = []
    next_token = None
    while True:
        kwargs = dict(params)
        if next_token:
            kwargs["nextToken"] = next_token
        resp = call(**kwargs)
        results.extend(resp.get(items_key, []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return results

CHECK = "channel-namespace-list-ordering"
GROUP = 'channel-namespace'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListChannelNamespaces returns exactly the three created namespaces on every call, in any
    order (AWS documents none); a duplicate name is refused without altering the list, and a
    deleted namespace 404s and leaves the other two listed."""
    svc = ctx.client("appsync")
    api = svc.create_api(
        name=ctx.unique_name("sim2real-behav-appsync-eventapi-"),
        eventConfig={"authProviders": [{"authType": "API_KEY"}, {"authType": "AWS_IAM"}], "connectionAuthModes": [{"authType": "API_KEY"}], "defaultPublishAuthModes": [{"authType": "API_KEY"}], "defaultSubscribeAuthModes": [{"authType": "API_KEY"}]},
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["api"]
    ctx.on_cleanup(lambda _a=api: svc.delete_api(apiId=_a["apiId"]))
    api_id = api["apiId"]

    base = _ns_name(ctx.unique_name("sim2real-behav-ns-"))[:46]
    names = [f"{base}a", f"{base}b", f"{base}c"]
    for name in names[:-1]:
        svc.create_channel_namespace(
            apiId=api_id,
            name=name,
            subscribeAuthModes=[{"authType": "API_KEY"}],
            publishAuthModes=[{"authType": "API_KEY"}],
            tags={"sim2real": CHECK, "sim2real:managed": "true"},
        )
        ctx.on_cleanup(lambda _n=name: svc.delete_channel_namespace(apiId=api_id, name=_n))
    svc.create_channel_namespace(
        apiId=api_id,
        name=names[-1],
        subscribeAuthModes=[{"authType": "API_KEY"}],
        publishAuthModes=[{"authType": "API_KEY"}],
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )

    listed = _list_all(lambda **kw: svc.list_channel_namespaces(apiId=api_id, **kw), "channelNamespaces")
    listed_names = [ns["name"] for ns in listed]
    assert listed_names == names or sorted(listed_names) == sorted(names), (
        f"expected ListChannelNamespaces to return exactly the created namespaces, "
        f"got {listed_names!r} (expected {names!r})"
    )

    listed2 = _list_all(lambda **kw: svc.list_channel_namespaces(apiId=api_id, **kw), "channelNamespaces")
    listed_names2 = [ns["name"] for ns in listed2]
    assert listed_names2 == names or sorted(listed_names2) == sorted(names), (
        f"expected a second ListChannelNamespaces call to return the same namespaces, "
        f"got {listed_names2!r} (expected {names!r})"
    )

    # Overly-permissive boundary: creating a channel namespace with a NAME that already exists on
    # this API must be rejected, not silently replace/duplicate the existing one.
    dup_code, dup_message = _error(
        lambda: svc.create_channel_namespace(
            apiId=api_id,
            name=names[0],
            subscribeAuthModes=[{"authType": "API_KEY"}],
            publishAuthModes=[{"authType": "API_KEY"}],
        )
    )
    assert dup_code == "ConflictException", (
        f"expected creating a channel namespace with an already-used name to fail with "
        f"ConflictException, got {dup_code}"
    )
    assert dup_message == "Channel namespace already exists.", (
        f"expected AWS's exact conflict message, got {dup_message!r}"
    )
    unchanged = _list_all(lambda **kw: svc.list_channel_namespaces(apiId=api_id, **kw), "channelNamespaces")
    assert [ns["name"] for ns in unchanged] == names or sorted(
        ns["name"] for ns in unchanged
    ) == sorted(names), (
        "a rejected duplicate-name CreateChannelNamespace call must not alter the existing list"
    )

    # Deletes prove gone, not just absent from a stale list: delete the last-created namespace,
    # confirm it 404s on an independent read, confirm the other two are still listed,
    # and confirm a second delete of the now-dead name also 404s rather than succeeding again.
    svc.delete_channel_namespace(apiId=api_id, name=names[-1])
    get_code, get_message = _error(lambda: svc.get_channel_namespace(apiId=api_id, name=names[-1]))
    assert get_code == "NotFoundException", (
        f"expected GetChannelNamespace on a deleted namespace to fail with NotFoundException, "
        f"got {get_code}"
    )
    assert get_message == "Channel namespace not found.", (
        f"expected AWS's exact not-found message, got {get_message!r}"
    )
    after_delete = _list_all(lambda **kw: svc.list_channel_namespaces(apiId=api_id, **kw), "channelNamespaces")
    assert [ns["name"] for ns in after_delete] == names[:-1] or sorted(
        ns["name"] for ns in after_delete
    ) == sorted(names[:-1]), (
        f"expected the remaining namespaces to stay listed after a delete, "
        f"got {[ns['name'] for ns in after_delete]!r} (expected {names[:-1]!r})"
    )
    redelete_code, redelete_message = _error(lambda: svc.delete_channel_namespace(apiId=api_id, name=names[-1]))
    assert redelete_code == "NotFoundException", (
        f"expected deleting an already-deleted namespace to fail with NotFoundException, "
        f"got {redelete_code}"
    )
    # AWS sends this refusal with no message body.
    assert redelete_message == "", f"expected an empty not-found message, got {redelete_message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
