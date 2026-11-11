"""list-pending-invitation-resources-unknown-invitation-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-pending-invitation-resources-unknown-invitation-rejected"
GROUP = "invitation-lifecycle"
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
    """ListPendingInvitationResources refuses an invitation ARN that was never
    issued, naming the exact ARN, while a share this account owns genuinely has no
    pending invitation to list for any resources."""
    ram = ctx.client("ram")

    fake_invitation_arn = (
        f"arn:aws:ram:{ctx.region}:{ctx.account}:resource-share-invitation/{uuid.uuid4()}"
    )
    code, message = _error(
        lambda: ram.list_pending_invitation_resources(resourceShareInvitationArn=fake_invitation_arn)
    )
    assert code == "ResourceShareInvitationArnNotFoundException", (
        f"expected ResourceShareInvitationArnNotFoundException, got {code}: {message!r}"
    )
    assert message == fake_invitation_arn, f"expected the message to name the ARN, got {message!r}"

    # Positive control: a real share this account owns has no invitation at all (it
    # named no principal), proving the invitation machinery itself is reachable and
    # that "not found" above was about this specific ARN, not a broken API path.
    name = ctx.unique_name("sim2real-ram-noinv-")
    share = ram.create_resource_share(
        name=name, tags=[{"key": "sim2real", "value": CHECK}]
    )["resourceShare"]
    share_arn = share["resourceShareArn"]
    ctx.on_cleanup(
        _teardown(lambda: ram.delete_resource_share(resourceShareArn=share_arn), "UnknownResourceException")
    )

    inv_pages = ram.get_paginator("get_resource_share_invitations").paginate(
        resourceShareArns=[share_arn]
    )
    invitations = [i for page in inv_pages for i in page["resourceShareInvitations"]]
    assert invitations == [], f"expected no invitation for a principal-less share, got {invitations!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
