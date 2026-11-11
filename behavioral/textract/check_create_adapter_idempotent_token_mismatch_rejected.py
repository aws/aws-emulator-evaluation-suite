"""create-adapter-idempotent-token-mismatch-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-adapter-idempotent-token-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["textract"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a ClientRequestToken with DIFFERENT CreateAdapter parameters is rejected with
    ValidationException, no second adapter is created, and re-using the same
    token with the ORIGINAL parameters still succeeds idempotently (positive control)."""
    textract = ctx.client("textract")
    token = ctx.unique_name("sim2real-token-")
    name = ctx.unique_name("sim2real-adapter-")

    first = textract.create_adapter(
        AdapterName=name,
        FeatureTypes=["QUERIES"],
        ClientRequestToken=token,
        Tags={"sim2real": CHECK},
    )
    adapter_id = first["AdapterId"]
    ctx.on_cleanup(lambda: textract.delete_adapter(AdapterId=adapter_id))

    other_name = name + "-different"
    err = _client_error(
        lambda: textract.create_adapter(
            AdapterName=other_name, FeatureTypes=["QUERIES"], ClientRequestToken=token
        )
    )
    assert err["Code"] == "ValidationException", (
        f"expected ValidationException, got {err['Code']!r}"
    )
    expected_message = "ClientRequestToken already sent with different parameters."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Effect absent: no adapter was created under the mismatched name.
    matches = 0
    next_token = None
    for _ in range(50):
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = textract.list_adapters(**kwargs)
        matches += sum(1 for a in resp.get("Adapters", []) if a["AdapterName"] == other_name)
        next_token = resp.get("NextToken")
        if not next_token:
            break
    assert matches == 0, "a mismatched-token create should not have created a new adapter"

    # Positive control: reusing the token with the ORIGINAL parameters still succeeds idempotently.
    second = textract.create_adapter(
        AdapterName=name,
        FeatureTypes=["QUERIES"],
        ClientRequestToken=token,
        Tags={"sim2real": CHECK},
    )
    assert second["AdapterId"] == adapter_id, (
        f"expected the idempotent replay to return the original AdapterId {adapter_id!r}, "
        f"got {second['AdapterId']!r}"
    )

    # Independent terminal read: exactly one adapter named `name` exists -- the restore call
    # did not silently create a second adapter alongside returning the original id.
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
