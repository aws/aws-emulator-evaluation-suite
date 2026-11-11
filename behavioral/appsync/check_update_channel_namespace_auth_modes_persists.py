"""update-channel-namespace-auth-modes-persists."""
from __future__ import annotations

import re

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

CHECK = "update-channel-namespace-auth-modes-persists"
GROUP = 'channel-namespace'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateChannelNamespace's new publishAuthModes are visible on a subsequent GetChannelNamespace."""
    svc = ctx.client("appsync")
    api = svc.create_api(name=ctx.unique_name("sim2real-behav-appsync-eventapi-"), eventConfig={"authProviders": [{"authType": "API_KEY"}, {"authType": "AWS_IAM"}], "connectionAuthModes": [{"authType": "API_KEY"}], "defaultPublishAuthModes": [{"authType": "API_KEY"}], "defaultSubscribeAuthModes": [{"authType": "API_KEY"}]}, tags={"team": "sim2real"})["api"]
    ctx.on_cleanup(lambda _a=api: svc.delete_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    name = _ns_name(ctx.unique_name("sim2real-behav-ns-"))

    svc.create_channel_namespace(apiId=api_id, name=name, publishAuthModes=[{"authType": "API_KEY"}])

    svc.update_channel_namespace(
        apiId=api_id, name=name, publishAuthModes=[{"authType": "AWS_IAM"}]
    )

    got = svc.get_channel_namespace(apiId=api_id, name=name)["channelNamespace"]
    auth_types = {m["authType"] for m in got["publishAuthModes"]}
    assert auth_types == {"AWS_IAM"}, f"expected publishAuthModes == {{'AWS_IAM'}} after update, got {auth_types}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
