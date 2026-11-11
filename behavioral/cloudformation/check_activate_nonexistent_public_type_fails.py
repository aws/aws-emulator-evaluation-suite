"""activate-nonexistent-public-type-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activate-nonexistent-public-type-fails"
GROUP = 'registry'
SERVICES = ['cloudformation']


def _client_error(fn, what):
    """Return (code, message) of the ClientError `fn` raises; raise AssertionError if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ActivateType is rejected for a syntactically valid but never-published public extension."""
    cf = ctx.client("cloudformation")
    bogus_public_arn = (
        f"arn:aws:cloudformation:{ctx.region}::type/resource/AWSSim2realBehav-Nope-Nope/00000001"
    )
    code, msg = _client_error(
        lambda: cf.activate_type(PublicTypeArn=bogus_public_arn),
        "ActivateType of a never-published public type",
    )
    # A bare `code is not None` would let an emulator pass by rejecting with ANY error (a generic
    # 500, a serialization fault); pin the registry-specific code real AWS uses.
    assert code == "CFNRegistryException", (
        f"expected CFNRegistryException activating a nonexistent "
        f"public type, got {code!r}"
    )
    assert msg == "TypeName is invalid", msg

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
