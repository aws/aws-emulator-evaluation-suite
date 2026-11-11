"""concurrent-oidc-thumbprint-update-conflict."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-oidc-thumbprint-update-conflict"
GROUP = "concurrency"
SERVICES = ["iam"]

RACER_COUNT = 8


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing UpdateOpenIDConnectProviderThumbprint calls each succeed or fail with
    ConcurrentModification and its exact message, and the provider ends with exactly one
    thumbprint, one a winning call sent."""
    iam = ctx.client("iam")
    url = f"https://{ctx.unique_name('sim2real-oidcracethumb-')}.example.com"
    provider_arn = _create_oidc_provider(ctx, url)

    racer_thumbprints = [_hex40(f"racer-{i}") for i in range(RACER_COUNT)]
    barrier = threading.Barrier(RACER_COUNT)

    def _racer(thumbprint: str):
        barrier.wait(timeout=10)
        iam.update_open_id_connect_provider_thumbprint(
            OpenIDConnectProviderArn=provider_arn, ThumbprintList=[thumbprint]
        )
        return thumbprint

    results = []
    with ThreadPoolExecutor(max_workers=RACER_COUNT) as ex:
        futures = [ex.submit(_racer, tp) for tp in racer_thumbprints]
        for f in futures:
            results.append(_outcome(f))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) >= 1, f"expected at least one winner, got results={results}"
    for _, code, message in failures:
        assert code == "ConcurrentModification", (
            f"expected only ConcurrentModification on losers, got {code!r} in {results}"
        )
        expected = "Too many operations are modifying this entity. Please try again later."
        assert message == expected, f"expected loser message {expected!r}, got {message!r}"

    final = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    final_thumbprints = final["ThumbprintList"]
    assert len(final_thumbprints) == 1, (
        f"expected exactly one stored thumbprint after the race, got {final_thumbprints!r}"
    )
    winning_thumbprints = {tp for _, tp in successes}
    assert final_thumbprints[0] in winning_thumbprints, (
        f"final thumbprint {final_thumbprints[0]!r} was not among the reported winners {winning_thumbprints!r}"
    )


def _hex40(seed: str) -> str:
    import hashlib

    return hashlib.sha1(seed.encode("utf-8")).hexdigest()


def _outcome(future):
    from botocore.exceptions import ClientError

    try:
        return ("ok", future.result())
    except ClientError as e:
        return ("error", e.response["Error"]["Code"], e.response["Error"].get("Message", ""))


def _create_oidc_provider(ctx, url: str) -> str:
    """Create a fresh OIDC provider at a per-run unique URL with a known initial
    thumbprint, registering cleanup."""
    iam = ctx.client("iam")
    resp = iam.create_open_id_connect_provider(
        Url=url, ThumbprintList=[_hex40("initial")], ClientIDList=["sim2real-behavioral-check"]
    )
    arn = resp["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
