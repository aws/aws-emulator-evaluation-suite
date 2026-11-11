"""detect-entities-concurrent-calls-return-isolated-results."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "detect-entities-concurrent-calls-return-isolated-results"
GROUP = "concurrency"
SERVICES = ["comprehendmedical"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Parallel DetectPHI calls each return only the name that was in their own request text."""
    cm = ctx.client("comprehendmedical")
    names = ["John Anderson", "Maria Garcia", "Robert Chen", "Susan Miller", "David Thompson"]
    texts = [f"Patient {name} was seen in clinic today for a routine checkup." for name in names]

    def _detect(text: str) -> dict:
        return cm.detect_phi(Text=text)

    with ThreadPoolExecutor(max_workers=len(texts)) as pool:
        results = list(pool.map(_detect, texts))

    for name, text, resp in zip(names, texts, results):
        name_entities = [e for e in resp["Entities"] if e["Type"] == "NAME"]
        assert name_entities, f"expected at least one NAME entity for text {text!r}, got {resp['Entities']}"
        # The model may split "Firstname Lastname" into one or two NAME entities (e.g. first/last
        # separately) -- reconstruct by joining in order and require it match the injected name.
        reconstructed = " ".join(e["Text"] for e in name_entities)
        assert reconstructed == name, (
            f"expected NAME entities to reconstruct to {name!r} for its own text, got {reconstructed!r} "
            "(cross-talk between concurrent requests)"
        )
        joined = " ".join(e["Text"] for e in resp["Entities"])
        for other_name in names:
            if other_name == name:
                continue
            assert other_name not in joined, f"response for {name!r} leaked unrelated name {other_name!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
