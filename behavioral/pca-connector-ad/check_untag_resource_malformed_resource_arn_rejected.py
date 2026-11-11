"""untag-resource-malformed-resource-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-malformed-resource-arn-rejected"
GROUP = "validation"
SERVICES = ["pca-connector-ad"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource rejects a malformed ResourceArn with BadRequestException "Invalid input resource
    arn: bad syntax", while a well-formed nonexistent connector ARN in the caller's account gets
    NotFoundException "Resource was not found"."""
    pcad = ctx.client("pca-connector-ad")
    account = ctx.client("sts").get_caller_identity()["Account"]

    code, message = _error_code(
        lambda: pcad.untag_resource(ResourceArn="definitely-not-an-arn", TagKeys=["k"])
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == "Invalid input resource arn: bad syntax", message

    control_code, control_message = _error_code(
        lambda: pcad.untag_resource(
            ResourceArn=(
                f"arn:aws:pca-connector-ad:{ctx.region}:{account}:connector/"
                "11111111-1111-1111-1111-111111111111"
            ),
            TagKeys=["k"],
        )
    )
    assert control_code == "NotFoundException", f"expected NotFoundException, got {control_code!r}"
    assert control_message == "Resource was not found", control_message


def _error_code(fn):
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        return type(exc).__name__, str(exc)
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

