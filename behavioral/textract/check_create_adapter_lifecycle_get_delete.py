"""create-adapter-lifecycle-get-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-adapter-lifecycle-get-delete"
GROUP = "adapter-lifecycle"
SERVICES = ["textract"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAdapter persists metadata visible via GetAdapter, and DeleteAdapter is a terminal
    deletion: the adapter is gone via an independent read AND unusable via a further mutation."""
    textract = ctx.client("textract")
    name = ctx.unique_name("sim2real-adapter-")
    created = textract.create_adapter(
        AdapterName=name,
        FeatureTypes=["QUERIES"],
        Description="sim2real fidelity test adapter",
        AutoUpdate="DISABLED",
        Tags={"env": "sim2real", "purpose": "fidelity-check"},
    )
    adapter_id = created["AdapterId"]

    def _cleanup():
        try:
            textract.delete_adapter(AdapterId=adapter_id)
        except textract.exceptions.ResourceNotFoundException:
            pass

    ctx.on_cleanup(_cleanup)

    got = textract.get_adapter(AdapterId=adapter_id)
    assert got["AdapterName"] == name, f"expected AdapterName {name!r}, got {got['AdapterName']!r}"
    assert got["FeatureTypes"] == ["QUERIES"], (
        f"expected FeatureTypes ['QUERIES'], got {got['FeatureTypes']!r}"
    )
    assert got["Description"] == "sim2real fidelity test adapter", (
        f"expected the description set at creation, got {got['Description']!r}"
    )
    assert got["AutoUpdate"] == "DISABLED", f"expected AutoUpdate DISABLED, got {got['AutoUpdate']!r}"
    assert "CreationTime" in got, "GetAdapter response is missing CreationTime"

    textract.delete_adapter(AdapterId=adapter_id)

    expected_message = "Adapter Id not found."
    err = _client_error(lambda: textract.get_adapter(AdapterId=adapter_id))
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected GetAdapter on a deleted adapter to fail ResourceNotFoundException, "
        f"got {err['Code']!r}"
    )
    assert err.get("Message") == expected_message, (
        f"expected GetAdapter message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Gone AND unusable: a further mutation on the dead id must also fail, not resurrect it.
    delete_again = _client_error(lambda: textract.delete_adapter(AdapterId=adapter_id))
    assert delete_again["Code"] == "ResourceNotFoundException", (
        f"expected a second DeleteAdapter on the same dead id to fail ResourceNotFoundException, "
        f"got {delete_again['Code']!r}"
    )
    assert delete_again.get("Message") == expected_message, (
        f"expected DeleteAdapter message {expected_message!r}, got {delete_again.get('Message')!r}"
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
