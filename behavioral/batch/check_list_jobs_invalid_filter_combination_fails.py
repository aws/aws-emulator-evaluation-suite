"""list-jobs-invalid-filter-combination-fails."""

from __future__ import annotations
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "list-jobs-invalid-filter-combination-fails"
GROUP = 'error-semantics'
SERVICES = ['batch']

def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message, RequestId). An unexpected success
    raises."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response.get("ResponseMetadata", {}).get("RequestId")
    raise AssertionError(f"expected a ClientError, call succeeded with {resp!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListJobs accepts exactly one filter mechanism (jobQueue/arrayJobId/multiNodeJobId);
    specifying zero, or more than one at once (an invalid combination), is rejected."""
    bat = ctx.client("batch")

    # Positive control: a single, syntactically valid filter mechanism is accepted even
    # when it names a job that does not exist -- this is what proves the rejections below
    # are specifically about the *filter selection*, not that ListJobs (or this account's
    # permission to call it) is broken outright.
    fake_id = str(uuid.uuid4())
    positive = bat.list_jobs(arrayJobId=fake_id)["jobSummaryList"]
    assert positive == [], f"expected empty jobSummaryList for a nonexistent arrayJobId, got {positive!r}"

    # Negative: specifying an invalid COMBINATION -- more than one filter mechanism at once --
    # is rejected, same as specifying none.
    combo_code, combo_message, combo_request_id = _error(
        lambda: bat.list_jobs(arrayJobId=fake_id, multiNodeJobId=fake_id)
    )
    assert combo_code == "ClientException", (
        f"expected ClientException for ListJobs with both arrayJobId and multiNodeJobId, got {combo_code!r}"
    )
    # Batch wraps these validation messages with the request id of the refused call.
    expected_combo = (
        "Error executing request, Exception : Array job id and multinode job id cannot both be set., "
        f"RequestId: {combo_request_id}"
    )
    assert combo_message == expected_combo, f"expected message {expected_combo!r}, got {combo_message!r}"

    # Negative: specifying none of jobQueue/arrayJobId/multiNodeJobId is also rejected.
    none_code, none_message, none_request_id = _error(lambda: bat.list_jobs())
    assert none_code == "ClientException", f"expected ClientException for ListJobs with no filter, got {none_code!r}"
    expected_none = f"Error executing request, Exception : Job queue name is required., RequestId: {none_request_id}"
    assert none_message == expected_none, f"expected message {expected_none!r}, got {none_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
