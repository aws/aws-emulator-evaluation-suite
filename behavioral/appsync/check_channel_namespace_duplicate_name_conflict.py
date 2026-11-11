"""channel-namespace-duplicate-name-conflict."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

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

def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target that accepts a call AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

CHECK = "channel-namespace-duplicate-name-conflict"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChannelNamespace reusing a name on the same Api fails ConflictException and leaves the
    original namespace as the only entry with its ARN; a different name on the same Api succeeds."""
    svc = ctx.client("appsync")
    api = svc.create_api(name=ctx.unique_name("sim2real-behav-appsync-eventapi-"), eventConfig={"authProviders": [{"authType": "API_KEY"}, {"authType": "AWS_IAM"}], "connectionAuthModes": [{"authType": "API_KEY"}], "defaultPublishAuthModes": [{"authType": "API_KEY"}], "defaultSubscribeAuthModes": [{"authType": "API_KEY"}]})["api"]
    ctx.on_cleanup(lambda _a=api: svc.delete_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    name = _ns_name(ctx.unique_name("sim2real-behav-ns-"))

    original = svc.create_channel_namespace(apiId=api_id, name=name)["channelNamespace"]
    ctx.on_cleanup(lambda: svc.delete_channel_namespace(apiId=api_id, name=name))

    code, message = _error(lambda: svc.create_channel_namespace(apiId=api_id, name=name))
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert message == "Channel namespace already exists.", (
        f"expected AWS's exact conflict message, got {message!r}"
    )

    namespaces = svc.list_channel_namespaces(apiId=api_id)["channelNamespaces"]
    matching = [ns for ns in namespaces if ns["name"] == name]
    assert len(matching) == 1, f"expected exactly one namespace named {name}, got {matching}"
    assert matching[0]["channelNamespaceArn"] == original["channelNamespaceArn"], (
        f"expected the surviving namespace's ARN to be the original {original['channelNamespaceArn']}, "
        f"got {matching[0]['channelNamespaceArn']}"
    )

    other_name = _ns_name(ctx.unique_name("sim2real-behav-otherns-"))
    other = svc.create_channel_namespace(apiId=api_id, name=other_name)["channelNamespace"]
    ctx.on_cleanup(lambda: svc.delete_channel_namespace(apiId=api_id, name=other_name))
    assert other["name"] == other_name, f"expected {other_name}, got {other['name']}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
