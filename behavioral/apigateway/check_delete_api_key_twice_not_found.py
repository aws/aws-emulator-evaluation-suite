"""delete-api-key-twice-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-api-key-twice-not-found"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting the same API key twice must fail the second time (overly-permissive check)."""
    ag = ctx.client("apigateway")
    created = ag.create_api_key(name=ctx.unique_name("sim2real-behav-apigw-key-double-"))
    key_id = created["id"]

    ag.delete_api_key(apiKey=key_id)
    code, message = _error(lambda: ag.delete_api_key(apiKey=key_id))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid API Key identifier specified", f"unexpected message: {message!r}"

    gone_code, gone_message = _error(lambda: ag.get_api_key(apiKey=key_id))
    assert gone_code == "NotFoundException", (
        f"key must remain gone after a rejected double-delete, got {gone_code}"
    )
    assert gone_message == "Invalid API Key identifier specified", (
        f"unexpected message: {gone_message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
