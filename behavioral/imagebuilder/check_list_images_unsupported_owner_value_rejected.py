"""list-images-unsupported-owner-value-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-images-unsupported-owner-value-rejected"
GROUP = "error-semantics"
SERVICES = ["imagebuilder"]

_REJECTED = ("InvalidParameterValueException",
             "The value supplied for parameter 'owner' is not valid. owner must be one of "
             "['Self', 'Shared', 'Amazon', 'ThirdParty', 'AWSMarketplace']")


def _error_code_and_message(fn):
    """The Error.Code and Error.Message ``fn`` raises; raises on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error_code_and_message(fn)
    assert got_code == code, f"expected error code {code!r}, got {got_code!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListImages rejects an owner value outside the Ownership enum; the same call with
    owner='Self' still answers 200.
    """
    ib = ctx.client("imagebuilder")

    expect_error(lambda: ib.list_images(owner="NotAnOwner"), *_REJECTED)

    # positive control: a modelled owner value succeeds on the identical shape of call,
    # filtered by a name this account never created
    name = ctx.unique_name("sim2real-ib-ownercontrol-")
    resp = ib.list_images(owner="Self", filters=[{"name": "name", "values": [name]}])
    assert resp["imageVersionList"] == [], (
        f"expected no image named {name!r}, got {resp['imageVersionList']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
