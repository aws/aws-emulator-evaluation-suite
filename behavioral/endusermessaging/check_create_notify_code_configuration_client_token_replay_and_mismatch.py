"""create-notify-code-configuration-client-token-replay-and-mismatch."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-notify-code-configuration-client-token-replay-and-mismatch"
GROUP = "notify-code-configurations"
SERVICES = ["endusermessaging"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A replayed create with the same client token returns the first configuration rather than
    a second; the token with a different name is refused and creates nothing.
    """
    eum = ctx.client("endusermessaging")
    token = ctx.unique_name("sim2real-behav-eum-cctok-")
    name = ctx.unique_name("sim2real-behav-eum-cctok-")
    first = eum.create_notify_code_configuration(notifyCodeConfigurationName=name,
                                                 clientToken=token)["notifyCodeConfiguration"]
    ccid = first["notifyCodeConfigurationId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_notify_code_configuration(notifyCodeConfigurationId=ccid),
                             "ResourceNotFoundException"))

    replay = eum.create_notify_code_configuration(notifyCodeConfigurationName=name,
                                                  clientToken=token)["notifyCodeConfiguration"]
    assert replay["notifyCodeConfigurationId"] == ccid, (
        "the replay must return the first configuration, not a second one"
    )

    other = ctx.unique_name("sim2real-behav-eum-cctok-other-")
    code, message = _error(lambda: eum.create_notify_code_configuration(
        notifyCodeConfigurationName=other, clientToken=token))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "The idempotency token and parameters presented do not match", (
        f"unexpected message {message!r}"
    )

    mine = []
    for page in eum.get_paginator("list_notify_code_configurations").paginate():
        mine.extend(c["notifyCodeConfigurationId"] for c in page["notifyCodeConfigurations"]
                    if c["notifyCodeConfigurationName"] in (name, other))
    assert mine == [ccid], f"exactly the first configuration must exist, found {len(mine)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
