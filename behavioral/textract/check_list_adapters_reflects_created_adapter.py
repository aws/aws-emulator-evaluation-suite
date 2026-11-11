"""list-adapters-reflects-created-adapter."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-adapters-reflects-created-adapter"
GROUP = "adapter-lifecycle"
SERVICES = ["textract"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created adapter shows up in ListAdapters (paginated) with the right name."""
    textract = ctx.client("textract")
    name = ctx.unique_name("sim2real-adapter-")
    adapter_id = textract.create_adapter(AdapterName=name, FeatureTypes=["QUERIES"])["AdapterId"]
    ctx.on_cleanup(lambda: textract.delete_adapter(AdapterId=adapter_id))

    found = None
    next_token = None
    for _ in range(50):
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = textract.list_adapters(**kwargs)
        for adapter in resp.get("Adapters", []):
            if adapter["AdapterId"] == adapter_id:
                found = adapter
                break
        if found is not None:
            break
        next_token = resp.get("NextToken")
        if not next_token:
            break

    assert found is not None, "created adapter did not appear in ListAdapters"
    assert found["AdapterName"] == name, f"expected AdapterName {name!r}, got {found['AdapterName']!r}"
    assert "CreationTime" in found, f"expected CreationTime in ListAdapters entry, got keys {sorted(found)}"
    assert found["FeatureTypes"] == ["QUERIES"], f"expected FeatureTypes ['QUERIES'], got {found['FeatureTypes']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
