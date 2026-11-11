"""api-key-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-key-lifecycle"
GROUP = 'api-keys'
SERVICES = ['apigateway']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApiKey -> GetApiKey reflects fields -> DeleteApiKey removes it and the id
    becomes unusable for a further mutation, not just for a read."""
    ag = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-apigw-key-")
    created = ag.create_api_key(name=name, enabled=True, tags={"sim2real": "api-key-lifecycle"})
    key_id = created["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ag.delete_api_key(apiKey=key_id)))

    got = ag.get_api_key(apiKey=key_id)
    assert got["name"] == name, f"expected name {name!r}, got {got['name']!r}"
    assert got["enabled"] is True, f"expected enabled True, got {got['enabled']!r}"

    ag.delete_api_key(apiKey=key_id)
    code, message = _error(lambda: ag.get_api_key(apiKey=key_id))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}: {message!r}"
    assert message == "Invalid API Key identifier specified", f"unexpected message {message!r}"

    # Gone must also mean unusable, not just unreadable.
    code, message = _error(
        lambda: ag.update_api_key(
            apiKey=key_id,
            patchOperations=[{"op": "replace", "path": "/enabled", "value": "false"}],
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException on dead id, got {code}: {message!r}"
    assert message == "Invalid API Key identifier specified", f"unexpected message {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
