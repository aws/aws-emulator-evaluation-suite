"""opensearch-native-search-roundtrip."""
from __future__ import annotations

import json
import time


from behavioral_harness import tags

CHECK = "opensearch-native-search-roundtrip"
GROUP = "server-side"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """A domain provisioned through the control plane must actually serve the native OpenSearch
    REST data plane: index a document via the domain's own endpoint (SigV4-signed) and read it
    back through `_search`. A backend that accepts CreateDomain/DescribeDomain but cannot serve real search traffic is a stub."""
    client = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-native-")
    _, endpoint = _create_minimal_domain(ctx, client, domain_name)

    driver = _native_roundtrip_with_retry(
        lambda: _opensearch_roundtrip(ctx, endpoint),
        "search",
    )
    assert driver == "driver:opensearch-py", f"unexpected round-trip driver result: {driver!r}"


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


def _domain_arn(ctx, domain_name):
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:es:{ctx.region}:{account}:domain/{domain_name}"


def _create_minimal_domain(ctx, client, domain_name):
    arn = _domain_arn(ctx, domain_name)
    account = arn.split(":")[4]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "es:*",
                "Resource": f"{arn}/*",
            }
        ],
    }
    client.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.19",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=json.dumps(policy),
        TagList=[{"Key": "sim2real", "Value": domain_name}],
    )
    ctx.on_cleanup(lambda: client.delete_domain(DomainName=domain_name))
    status = _poll_until(
        lambda: client.describe_domain(DomainName=domain_name)["DomainStatus"],
        lambda s: s.get("Created") is True and not s.get("Processing", False) and s.get("Endpoint"),
        timeout_s=1800.0,
        interval_s=30.0,
    )
    return status["ARN"], status.get("Endpoint")


def _native_roundtrip_with_retry(roundtrip, label, *, budget_s=180):
    """Run *roundtrip* (a zero-arg callable), retrying connection warm-up until *budget_s*.

    A missing driver fails at once, an ``AssertionError`` (connected but served wrong data) fails
    at once, and anything else is retried as endpoint warm-up and fails at the deadline.
    """
    deadline = time.monotonic() + budget_s
    while True:
        try:
            return roundtrip()
        except ImportError:
            raise
        except AssertionError:
            raise
        except Exception as exc:  # noqa: BLE001 -- endpoint warm-up, retry
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"could not complete {label} round-trip within {budget_s}s: {exc!r}"
                ) from exc
            time.sleep(2)


def _ctx_credentials(ctx):
    """botocore Credentials for the ctx's own identity, for the native protocol that signs its own
    requests (OpenSearch SigV4): read off a ctx client's signer, so every target signs as the
    identity ctx.client signs with and never as an ambient credential chain."""
    from botocore.credentials import Credentials

    frozen = ctx.client("opensearch")._request_signer._credentials.get_frozen_credentials()
    return Credentials(frozen.access_key, frozen.secret_key, frozen.token)


def _opensearch_roundtrip(ctx, endpoint, *, index="sim2real-dp") -> str:
    """Index a document then read it back through `_search` -- the native OpenSearch data plane,
    signed with SigV4 for the ctx's own identity. ImportError if `opensearch-py` is absent.

    *endpoint* is taken as a URL, not as a hostname: transport is DERIVED from it rather than assumed
    to be TLS on 443. Real AWS returns a bare `search-*.es.amazonaws.com` (no scheme, no port) which
    still resolves to https/443, but an emulator's endpoint is typically a plaintext container on
    another port, so the transport is derived from the URL rather than assumed.
    """
    from urllib.parse import urlparse

    from opensearchpy import AWSV4SignerAuth, OpenSearch, RequestsHttpConnection

    raw = str(ctx.endpoint_url(endpoint)).rstrip("/")
    parsed = urlparse(raw if "//" in raw else f"//{raw}")  # `//` so a bare host parses as netloc
    use_ssl = parsed.scheme != "http"
    verify = ctx.http_verify
    client = OpenSearch(
        hosts=[{"host": parsed.hostname or raw, "port": parsed.port or (443 if use_ssl else 80)}],
        http_auth=AWSV4SignerAuth(_ctx_credentials(ctx), ctx.region, "es"),
        use_ssl=use_ssl, verify_certs=use_ssl and verify is not False,
        **({"ca_certs": verify} if isinstance(verify, str) else {}),
        connection_class=RequestsHttpConnection, timeout=30,
    )
    try:
        client.index(index=index, id="1", body={"val": "sim2real"}, refresh=True)
        hits = client.search(index=index, body={"query": {"match": {"val": "sim2real"}}})
        total = hits.get("hits", {}).get("total", {}).get("value", 0)
        assert total >= 1, f"indexed document was not searchable: {hits!r}"
        src = hits["hits"]["hits"][0]["_source"]
        assert src.get("val") == "sim2real", f"document did not round-trip: {src!r}"
        return "driver:opensearch-py"
    finally:
        # Delete the index, not just the doc: this helper runs inside a retry loop, so a left-behind
        # index would make the next attempt's "was it searchable" assertion pass on stale data.
        try:
            client.indices.delete(index=index, ignore_unavailable=True)
        except Exception:  # noqa: BLE001 -- teardown must not mask the round-trip verdict
            pass
        client.close()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
