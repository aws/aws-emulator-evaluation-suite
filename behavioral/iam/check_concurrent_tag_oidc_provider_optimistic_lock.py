"""concurrent-tag-oidc-provider-optimistic-lock."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-tag-oidc-provider-optimistic-lock"
GROUP = "concurrency"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Simultaneous TagOpenIDConnectProvider calls: losers get ConcurrentModification, at least
    one writer wins, and the final tag value is one a successful writer sent."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-oidctagrace-")
    url = f"https://{name}.example.com"
    thumbprint = "c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7"

    created = iam.create_open_id_connect_provider(Url=url, ThumbprintList=[thumbprint])
    arn = created["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn))

    racer_count = 8
    barrier = threading.Barrier(racer_count)
    results: list[tuple[str, str]] = [("", "")] * racer_count

    def racer(i: int) -> None:
        value = f"v{i}"
        barrier.wait()
        try:
            iam.tag_open_id_connect_provider(
                OpenIDConnectProviderArn=arn, Tags=[{"Key": "Racer", "Value": value}]
            )
            results[i] = ("ok", value)
        except ClientError as exc:
            results[i] = ("error", exc.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        list(pool.map(racer, range(racer_count)))

    successes = [value for status, value in results if status == "ok"]
    failures = [code for status, code in results if status == "error"]

    for code in failures:
        assert code == "ConcurrentModification", (
            f"expected only ConcurrentModification for losing racers, got {code!r}"
        )
    assert len(successes) >= 1, "at least one concurrent TagOpenIDConnectProvider call must succeed"

    final_tags = {
        t["Key"]: t["Value"]
        for t in iam.list_open_id_connect_provider_tags(OpenIDConnectProviderArn=arn)["Tags"]
    }
    assert "Racer" in final_tags, "Racer tag missing after concurrent tagging"
    assert final_tags["Racer"] in successes, (
        f"final tag value {final_tags['Racer']!r} does not match any successful writer's "
        f"value {successes!r}; indicates corruption or a silent lost update"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
