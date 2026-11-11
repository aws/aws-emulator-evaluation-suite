"""list-adapter-versions-empty-for-new-adapter."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-adapter-versions-empty-for-new-adapter"
GROUP = "adapter-lifecycle"
SERVICES = ["textract"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created adapter with no trained versions reports an empty AdapterVersions list,
    and once the adapter itself is deleted, listing its versions is refused as not-found."""
    textract = ctx.client("textract")
    name = ctx.unique_name("sim2real-adapter-")
    adapter_id = textract.create_adapter(
        AdapterName=name,
        FeatureTypes=["QUERIES"],
        Tags={"env": "sim2real", "purpose": "fidelity-check"},
    )["AdapterId"]

    def _cleanup():
        try:
            textract.delete_adapter(AdapterId=adapter_id)
        except textract.exceptions.ResourceNotFoundException:
            pass

    ctx.on_cleanup(_cleanup)

    resp = textract.list_adapter_versions(AdapterId=adapter_id)
    assert resp["AdapterVersions"] == [], (
        f"expected no versions for a freshly created adapter, got {resp['AdapterVersions']}"
    )
    assert resp.get("NextToken") is None, f"expected no NextToken, got {resp.get('NextToken')!r}"

    textract.delete_adapter(AdapterId=adapter_id)

    err = _client_error(lambda: textract.list_adapter_versions(AdapterId=adapter_id))
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException listing versions of a deleted adapter, "
        f"got {err['Code']!r}"
    )
    expected_message = "Adapter Id not found."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return the botocore Error dict (Code and Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
