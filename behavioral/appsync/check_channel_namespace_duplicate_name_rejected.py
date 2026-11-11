"""channel-namespace-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "channel-namespace-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChannelNamespace with a name already used on the same Event API fails ConflictException,
    leaving exactly one namespace of that name; a different name on the same API still succeeds."""
    appsync = ctx.client("appsync")

    event_config = {
        "authProviders": [{"authType": "API_KEY"}],
        "connectionAuthModes": [{"authType": "API_KEY"}],
        "defaultPublishAuthModes": [{"authType": "API_KEY"}],
        "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
    }
    api_name = ctx.unique_name("sim2real-nsdup-")
    api = appsync.create_api(
        name=api_name,
        eventConfig=event_config,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["api"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))

    ns_name = _safe_channel_name(ctx, "dupns")
    original = appsync.create_channel_namespace(apiId=api_id, name=ns_name)["channelNamespace"]
    ctx.on_cleanup(lambda: appsync.delete_channel_namespace(apiId=api_id, name=ns_name))

    code, message = _error(lambda: appsync.create_channel_namespace(apiId=api_id, name=ns_name))
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert message == "Channel namespace already exists.", (
        f"expected AWS's exact conflict message, got {message!r}"
    )

    namespaces = appsync.list_channel_namespaces(apiId=api_id)["channelNamespaces"]
    matching = [ns for ns in namespaces if ns["name"] == ns_name]
    assert len(matching) == 1, f"expected exactly one namespace named {ns_name}, got {matching}"
    assert matching[0]["channelNamespaceArn"] == original["channelNamespaceArn"], (
        f"expected the survivor's ARN to be the original {original['channelNamespaceArn']!r}, "
        f"got {matching[0]['channelNamespaceArn']!r}"
    )

    other_name = _safe_channel_name(ctx, "otherns")
    other = appsync.create_channel_namespace(apiId=api_id, name=other_name)["channelNamespace"]
    ctx.on_cleanup(lambda: appsync.delete_channel_namespace(apiId=api_id, name=other_name))

    # Independent terminal read at the destination: get_channel_namespace (not the
    # create response) must show the new, distinctly-named namespace actually landed.
    fetched = appsync.get_channel_namespace(apiId=api_id, name=other_name)["channelNamespace"]
    assert fetched["channelNamespaceArn"] == other["channelNamespaceArn"], (
        f"expected {other_name} to be independently readable with ARN "
        f"{other['channelNamespaceArn']!r}, got {fetched!r}"
    )


def _safe_channel_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    cleaned = "".join(c if c.isalnum() else "-" for c in raw)
    cleaned = cleaned.strip("-") or "ns0"
    return cleaned[:50]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target that accepts a call AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
