"""create-adapter-idempotent-token-returns-same-adapter."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-adapter-idempotent-token-returns-same-adapter"
GROUP = "adapter-lifecycle"
SERVICES = ["textract"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-using the same ClientRequestToken with identical CreateAdapter params returns the same AdapterId."""
    textract = ctx.client("textract")
    name = ctx.unique_name("sim2real-adapter-")
    token = ctx.unique_name("sim2real-token-")

    tags = {"sim2real": "create-adapter-idempotent-token-returns-same-adapter"}
    first = textract.create_adapter(
        AdapterName=name, FeatureTypes=["QUERIES"], ClientRequestToken=token, Tags=tags
    )
    adapter_id = first["AdapterId"]
    ctx.on_cleanup(lambda: textract.delete_adapter(AdapterId=adapter_id))

    second = textract.create_adapter(
        AdapterName=name, FeatureTypes=["QUERIES"], ClientRequestToken=token, Tags=tags
    )
    assert second["AdapterId"] == adapter_id, (
        f"expected reusing ClientRequestToken to return the same AdapterId "
        f"{adapter_id!r}, got {second['AdapterId']!r}"
    )

    # Exactly one adapter with this name should exist (no duplicate was created).
    matches = 0
    next_token = None
    for _ in range(50):
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = textract.list_adapters(**kwargs)
        matches += sum(1 for a in resp.get("Adapters", []) if a["AdapterName"] == name)
        next_token = resp.get("NextToken")
        if not next_token:
            break
    assert matches == 1, f"expected exactly 1 adapter named {name!r}, found {matches}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
