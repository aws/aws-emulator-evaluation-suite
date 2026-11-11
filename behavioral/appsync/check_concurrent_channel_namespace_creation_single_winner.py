"""concurrent-channel-namespace-creation-single-winner."""
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

CHECK = "concurrent-channel-namespace-creation-single-winner"
GROUP = 'concurrency'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateChannelNamespace calls with the same name: exactly one wins, rest get ConflictException."""
    svc = ctx.client("appsync")
    from concurrent.futures import ThreadPoolExecutor

    from botocore.exceptions import ClientError

    api = svc.create_api(name=ctx.unique_name("sim2real-behav-appsync-eventapi-"), eventConfig={"authProviders": [{"authType": "API_KEY"}, {"authType": "AWS_IAM"}], "connectionAuthModes": [{"authType": "API_KEY"}], "defaultPublishAuthModes": [{"authType": "API_KEY"}], "defaultSubscribeAuthModes": [{"authType": "API_KEY"}]}, tags={"sim2real": CHECK})["api"]
    ctx.on_cleanup(lambda _a=api: svc.delete_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    name = _ns_name(ctx.unique_name("sim2real-behav-ns-"))
    racers = 5

    def attempt(_i):
        try:
            svc.create_channel_namespace(apiId=api_id, name=name, tags={"sim2real": CHECK})
            return None  # success
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")

    with ThreadPoolExecutor(max_workers=racers) as pool:
        outcomes = list(pool.map(attempt, range(racers)))

    successes = [o for o in outcomes if o is None]
    failures = [o for o in outcomes if o is not None]

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {outcomes}"
    assert len(failures) == racers - 1, f"expected {racers - 1} failures, got {failures}"
    assert all(c == "ConflictException" for c, _m in failures), failures
    assert all(m == "Channel namespace already exists." for _c, m in failures), failures

    names = [n["name"] for n in svc.list_channel_namespaces(apiId=api_id)["channelNamespaces"]]
    assert names.count(name) == 1, f"expected exactly 1 channel namespace named {name!r}, got {names.count(name)} (names={names})"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
