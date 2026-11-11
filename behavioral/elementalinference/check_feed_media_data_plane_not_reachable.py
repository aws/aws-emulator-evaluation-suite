"""feed-media-data-plane-not-reachable."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from behavioral_harness import tags

CHECK = "feed-media-data-plane-not-reachable"
GROUP = "native-protocol"
SERVICES = ["elementalinference"]


def _subtitling_output(name: str, language: str = "eng") -> dict:
    return {"name": name, "outputConfig": {"subtitling": {"language": language}}, "status": "ENABLED"}


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _sigv4_post(ctx, signing_name: str, url: str, body: dict) -> tuple[int, bytes]:
    """Sign and send a real request against the feed's data-plane REST API (CMAF ingest / GetMetadata),
    the same way the docs' `awscurl --service elemental-inference` examples do -- no boto3 operation model
    exists for this API, so the request is hand-signed with the runner's credentials (ctx.subprocess_env()).
    """
    env = ctx.subprocess_env()
    creds = Credentials(
        access_key=env["AWS_ACCESS_KEY_ID"],
        secret_key=env["AWS_SECRET_ACCESS_KEY"],
        token=env.get("AWS_SESSION_TOKEN"),
    )
    payload = json.dumps(body).encode("utf-8")
    request = AWSRequest(method="POST", url=url, data=payload, headers={"Content-Type": "application/json"})
    SigV4Auth(creds, signing_name, ctx.region).add_auth(request)
    prepared = request.prepare()
    target, route = ctx.endpoint_route(prepared.url)
    http_req = urllib.request.Request(
        target, data=payload, headers=dict(prepared.headers, **route), method="POST"
    )
    try:
        with urllib.request.urlopen(http_req, timeout=20) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A signed GetMetadata POST to a feed's advertised dataEndpoint answers 200 with an items list, or 400/404
    with a JSON error message, rather than refusing the connection or failing with another status."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-feed-")
    output_name = "sub1"
    feed_id = ei.create_feed(
        name=name,
        outputs=[_subtitling_output(output_name)],
        tags={"Environment": "sim2real-behav"},
    )["id"]
    ctx.on_cleanup(lambda: ei.delete_feed(id=feed_id))

    resource_name = ctx.unique_name("sim2real-ei-src-")
    ei.associate_feed(id=feed_id, associatedResourceName=resource_name, outputs=[])
    got = _poll_until(lambda: ei.get_feed(id=feed_id), lambda r: r["status"] == "ACTIVE")

    data_endpoint = ctx.endpoint_url(got["dataEndpoints"][0])
    url = f"{data_endpoint}/v1/feed/{feed_id}/input/0/metadata"
    body = {
        "outputName": output_name,
        "timeSpecification": {"ptsBased": {"startPts": 0, "endPts": 1001, "timescale": 1000}},
    }

    status, raw = _sigv4_post(ctx, ei.meta.service_model.signing_name, url, body)
    # No real media is flowing into this feed (there's no MediaLive channel actually streaming), so
    # Elemental Inference cannot have produced metadata yet. The behavioral contract we actually want to
    # verify is that the advertised dataEndpoint is a REAL, sigv4-signed, reachable REST endpoint (not just
    # an opaque string in the control-plane response) that validates the request instead of refusing the
    # connection or timing out. A backend that fakes CreateFeed/AssociateFeed without ever serving this
    # data-plane endpoint fails here (connection error / 5xx) instead of only ever passing control-plane
    # smoke tests.
    assert status in (200, 400, 404), (
        f"signed GetMetadata request against the feed's data endpoint {data_endpoint!r} returned "
        f"unexpected HTTP {status} (expected a real validated response, not a dead/broken endpoint): {raw[:500]!r}"
    )
    parsed = json.loads(raw)
    if status == 200:
        assert "items" in parsed and isinstance(parsed["items"], list), f"malformed metadata response body: {parsed!r}"
    else:
        assert "message" in parsed or "Message" in parsed, f"malformed error response body: {parsed!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
