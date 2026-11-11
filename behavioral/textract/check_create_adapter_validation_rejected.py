"""create-adapter-validation-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-adapter-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["textract"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAdapter rejects an AdapterName that violates the ^[a-zA-Z0-9-_]+$ pattern with
    InvalidParameterException, no adapter is created, and an otherwise-identical valid request
    (the positive control) succeeds."""
    textract = ctx.client("textract")
    invalid_name = ctx.unique_name("sim2real adapter ") + "!!invalid!!"

    err = _client_error(
        lambda: textract.create_adapter(AdapterName=invalid_name, FeatureTypes=["QUERIES"])
    )
    assert err["Code"] == "InvalidParameterException", (
        f"expected InvalidParameterException, got {err['Code']!r}"
    )
    expected_message = "Request has invalid parameters"
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Effect absent: nothing was created under that (invalid) name.
    matches = 0
    next_token = None
    for _ in range(50):
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = textract.list_adapters(**kwargs)
        matches += sum(1 for a in resp.get("Adapters", []) if a["AdapterName"] == invalid_name)
        next_token = resp.get("NextToken")
        if not next_token:
            break
    assert matches == 0, f"expected 0 adapters named {invalid_name!r}, found {matches}"

    # Positive control: a valid AdapterName with the same FeatureTypes succeeds.
    valid_name = ctx.unique_name("sim2real-adapter-")
    adapter_id = textract.create_adapter(
        AdapterName=valid_name,
        FeatureTypes=["QUERIES"],
        Tags={"env": "sim2real", "purpose": "fidelity-check"},
    )["AdapterId"]
    ctx.on_cleanup(lambda: textract.delete_adapter(AdapterId=adapter_id))
    got = textract.get_adapter(AdapterId=adapter_id)
    assert got["AdapterName"] == valid_name, (
        f"expected GetAdapter to report AdapterName={valid_name!r}, got {got['AdapterName']!r}"
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
