"""concurrent-duplicate-analyzer-creation-exactly-one-succeeds."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-duplicate-analyzer-creation-exactly-one-succeeds"
GROUP = "concurrency"
SERVICES = ["accessanalyzer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """Racing N CreateAnalyzer calls for the same analyzerName (each with its own
    auto-generated idempotency token) must yield exactly one winner; every other racer
    gets ConflictException for the duplicate name, never a second distinct analyzer."""
    aa = ctx.client("accessanalyzer")
    name = ctx.unique_name("sim2real-aa-race-")
    racers = 5

    def _attempt():
        try:
            arn = aa.create_analyzer(
                analyzerName=name, type="ACCOUNT", tags={"sim2real-env": "behavioral"}
            )["arn"]
            return ("ok", arn)
        except ClientError as e:
            err = e.response["Error"]
            return ("error", (err["Code"], err.get("Message")))

    with ThreadPoolExecutor(max_workers=racers) as pool:
        futures = [pool.submit(_attempt) for _ in range(racers)]
        results = [f.result() for f in as_completed(futures)]

    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=name))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly 1 winner among {racers} racers, got {successes}"
    assert len(failures) == racers - 1, f"expected {racers - 1} losers, got {failures}"
    expected = ("ConflictException", "Analyzer with the same name already exists")
    assert all(detail == expected for _, detail in failures), failures

    listed = aa.list_analyzers(type="ACCOUNT")["analyzers"]
    matching = [a for a in listed if a["name"] == name]
    assert len(matching) == 1, f"expected exactly one analyzer named {name}, found {matching}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
