"""get-api-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-api-not-found"
GROUP = 'error-semantics'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetApi rejects a bogus id with NotFoundException -- but only once a positive
    control proves GetApi succeeds for a real one, and the same id fails identically
    (and drops off the list) once that real Api is deleted."""
    agw = ctx.client("apigatewayv2")

    name = ctx.unique_name("sim2real-behav-agwv2-")
    real_id = agw.create_api(Name=name, ProtocolType="HTTP", Tags=TAGS)["ApiId"]
    ctx.on_cleanup(lambda: _swallow(lambda: agw.delete_api(ApiId=real_id)))

    # Positive control: credentials and endpoint work, so a rejection below is about
    # THIS id, not about GetApi being universally denied.
    control = agw.get_api(ApiId=real_id)
    assert control["ApiId"] == real_id, (
        f"expected GetApi to echo {real_id}, got {control.get('ApiId')}"
    )

    bogus_id = "bogus-" + real_id
    code, message = _error(lambda: agw.get_api(ApiId=bogus_id))
    assert code == "NotFoundException", (
        f"expected NotFoundException for a bogus id, got {code}: {message!r}"
    )
    assert message == f"Invalid API identifier specified {ctx.account}:{bogus_id}", (
        f"expected the exact invalid-API-identifier message for {bogus_id}, got {message!r}"
    )

    # Delete proves gone: the same, previously-valid id now fails identically and
    # disappears from the list.
    agw.delete_api(ApiId=real_id)
    code_after_delete, message_after_delete = _error(lambda: agw.get_api(ApiId=real_id))
    assert code_after_delete == "NotFoundException", (
        f"expected NotFoundException after delete, got {code_after_delete}: {message_after_delete!r}"
    )
    assert message_after_delete == f"Invalid API identifier specified {ctx.account}:{real_id}", (
        f"expected the deleted id to fail with the same message shape, got {message_after_delete!r}"
    )
    remaining_ids = [a["ApiId"] for a in agw.get_apis().get("Items", [])]
    assert real_id not in remaining_ids, f"deleted api {real_id} still listed"


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """Call fn; return the ClientError (code, message). An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected ClientError, call unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
