"""channel-namespace-lifecycle."""
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
    because a target that accepts a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

CHECK = "channel-namespace-lifecycle"
GROUP = 'channel-namespace'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannelNamespace -> Get/List reflect it -> DeleteChannelNamespace -> Get is NotFound."""
    svc = ctx.client("appsync")
    api = svc.create_api(name=ctx.unique_name("sim2real-behav-appsync-eventapi-"), eventConfig={"authProviders": [{"authType": "API_KEY"}, {"authType": "AWS_IAM"}], "connectionAuthModes": [{"authType": "API_KEY"}], "defaultPublishAuthModes": [{"authType": "API_KEY"}], "defaultSubscribeAuthModes": [{"authType": "API_KEY"}]})["api"]
    ctx.on_cleanup(lambda _a=api: svc.delete_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    name = _ns_name(ctx.unique_name("sim2real-behav-ns-"))

    svc.create_channel_namespace(apiId=api_id, name=name)

    got = svc.get_channel_namespace(apiId=api_id, name=name)["channelNamespace"]
    assert got["name"] == name, f"expected get_channel_namespace name={name!r}, got {got.get('name')!r}"

    names = [n["name"] for n in svc.list_channel_namespaces(apiId=api_id)["channelNamespaces"]]
    assert name in names, f"expected {name!r} in list_channel_namespaces names, got {names!r}"

    svc.delete_channel_namespace(apiId=api_id, name=name)
    code, message = _error(lambda: svc.get_channel_namespace(apiId=api_id, name=name))
    assert code == "NotFoundException", f"expected NotFoundException reading deleted namespace {name!r}, got {code!r}"
    assert message == "Channel namespace not found.", (
        f"expected AWS's exact not-found message, got {message!r}"
    )

    # A mutation on the dead id must also fail, not just a read.
    update_code, update_message = _error(
        lambda: svc.update_channel_namespace(apiId=api_id, name=name, publishAuthModes=[{"authType": "API_KEY"}])
    )
    assert update_code == "NotFoundException", (
        f"expected NotFoundException updating deleted namespace {name!r}, got {update_code!r}"
    )
    # AWS sends this refusal with no message body.
    assert update_message == "", f"expected an empty not-found message, got {update_message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
