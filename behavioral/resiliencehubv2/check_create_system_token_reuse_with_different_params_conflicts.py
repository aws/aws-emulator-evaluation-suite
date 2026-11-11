"""create-system-token-reuse-with-different-params-conflicts."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-system-token-reuse-with-different-params-conflicts"
GROUP = 'idempotency'
SERVICES = ['resiliencehubv2']


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
    """(Error.Code, Error.Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a CreateSystem clientToken with a DIFFERENT name is refused with ConflictException
    naming the token, and the system the token already minted is left exactly as it was -- the
    comparison that proves the second call changed nothing is only visible across two calls."""
    rh = ctx.client("resiliencehubv2")
    name = ctx.unique_name("sim2real-behav-rhv2-")
    other_name = ctx.unique_name("sim2real-behav-rhv2-")
    token = ctx.unique_name("sim2real-behav-rhv2-tok-")

    first = rh.create_system(name=name, clientToken=token)["system"]
    ctx.on_cleanup(_teardown(
        lambda: rh.delete_system(systemArn=first["systemArn"]), "ResourceNotFoundException"
    ))

    code, message = _error(lambda: rh.create_system(name=other_name, clientToken=token))
    assert code == "ConflictException", (
        f"reusing clientToken {token!r} with a different name must be refused with "
        f"ConflictException, got {code}: {message!r}"
    )
    assert message == (
        f"Got two different request with the same token: {token}, please use a different token"
    ), f"unexpected message {message!r}"

    # The positive control: the original system is untouched by the refused call.
    unchanged = rh.get_system(systemArn=first["systemArn"])["system"]
    assert unchanged["name"] == name, (
        f"the system the token originally minted must still be named {name!r}, got "
        f"{unchanged['name']!r} -- a refused reuse of the token must not mutate it"
    )
    assert unchanged["systemId"] == first["systemId"], (
        f"the system's id must stay {first['systemId']!r}, got {unchanged['systemId']!r}"
    )

    # And the name the refused call tried to use was never created under any id.
    page = rh.list_systems()["systemSummaries"]
    assert not any(s["name"] == other_name for s in page), (
        f"ListSystems must show no system named {other_name!r}; the refused create must not "
        f"have minted a resource under that name: {page!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
