"""list-retirable-grants-invalid-marker-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-retirable-grants-invalid-marker-rejected"
GROUP = "error-semantics"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRetirableGrants with a never-issued Marker fails with InvalidMarkerException and an
    empty message; the same call without the Marker succeeds."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    retiring_principal = sts.get_caller_identity()["Arn"]

    code, message = _error(
        lambda: kms.list_retirable_grants(
            RetiringPrincipal=retiring_principal, Marker="not-a-real-pagination-token-xyz"
        )
    )
    assert code == "InvalidMarkerException", (
        f"expected InvalidMarkerException for a corrupted Marker, got {code!r}"
    )
    # AWS sends this refusal with no message text.
    assert message == "", f"expected an empty message, got {message!r}"

    resp = kms.list_retirable_grants(RetiringPrincipal=retiring_principal)
    assert "Grants" in resp, (
        f"expected a 'Grants' key once the corrupted Marker is omitted, got keys={list(resp.keys())}"
    )


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
