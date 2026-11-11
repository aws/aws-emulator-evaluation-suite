"""hook-result-and-handler-progress-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hook-result-and-handler-progress-lifecycle"
GROUP = 'hooks'
SERVICES = ['cloudformation']


def _client_error(fn):
    """Call fn(); return botocore (Code, Message) of the ClientError it raises. An unexpected
    SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListHookResults/GetHookResult only surface results for real invocations;
    RecordHandlerProgress rejects a bearer token with no live provisioning request."""
    cf = ctx.client("cloudformation")

    # The account's hook history is shared state this check does not own, so
    # only the listing's shape is graded.
    results = cf.list_hook_results()
    assert isinstance(results.get("HookResults"), list), (
        f"expected a HookResults list, got {results!r}"
    )

    bogus_id = "00000000-0000-0000-0000-000000000000"
    code, message = _client_error(lambda: cf.get_hook_result(HookResultId=bogus_id))
    assert code == "HookResultNotFound", (
        f"expected HookResultNotFound for an unissued HookResultId, got {code!r}"
    )
    assert message == "The hook result was not found.", message

    bogus_token = ctx.unique_name("sim2real-behav-bearer-")
    code2, message2 = _client_error(
        lambda: cf.record_handler_progress(BearerToken=bogus_token, OperationStatus="SUCCESS")
    )
    assert code2 == "ValidationError", (
        f"RecordHandlerProgress with an unrecognized bearer token must be rejected "
        f"with ValidationError, got {code2!r}"
    )
    assert message2 == f"BearerToken '{bogus_token}' is invalid", message2

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
