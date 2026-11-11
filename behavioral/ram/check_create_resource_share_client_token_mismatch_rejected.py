"""create-resource-share-client-token-mismatch-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-resource-share-client-token-mismatch-rejected"
GROUP = "resource-share-lifecycle"
SERVICES = ["ram"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Replaying a CreateResourceShare clientToken with different request parameters
    is rejected, while replaying it with the identical request is idempotent."""
    ram = ctx.client("ram")

    name = ctx.unique_name("sim2real-ram-token-")
    token = str(uuid.uuid4())
    share = ram.create_resource_share(
        name=name, clientToken=token, tags=[{"key": "sim2real", "value": CHECK}]
    )["resourceShare"]
    share_arn = share["resourceShareArn"]
    ctx.on_cleanup(
        _teardown(lambda: ram.delete_resource_share(resourceShareArn=share_arn), "UnknownResourceException")
    )

    code, message = _error(
        lambda: ram.create_resource_share(name=name + "-different", clientToken=token)
    )
    assert code == "IdempotentParameterMismatchException", (
        f"expected IdempotentParameterMismatchException, got {code}: {message!r}"
    )
    assert message == (
        "The request has the same client token as a previous request, but the "
        "requests are not the same."
    ), f"unexpected message {message!r}"

    # Positive control: replaying the SAME request with the same token is idempotent
    # and returns the original share rather than failing or creating a second one.
    replay = ram.create_resource_share(
        name=name, clientToken=token, tags=[{"key": "sim2real", "value": CHECK}]
    )["resourceShare"]
    assert replay["resourceShareArn"] == share_arn, (
        f"expected the identical replay to return {share_arn!r}, got {replay['resourceShareArn']!r}"
    )

    shares = ram.get_resource_shares(name=name, resourceOwner="SELF")["resourceShares"]
    matching = [s for s in shares if s["resourceShareArn"] == share_arn]
    assert len(matching) == 1, (
        f"expected exactly one share named {name!r} to exist, got {len(matching)}: {shares!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
