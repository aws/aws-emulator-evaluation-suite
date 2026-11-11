"""op-studio-unknown-id-operations-fail."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")


def _studio_missing_message(message):
    """EMR Studio's refusal for an unknown StudioId. It embeds the backend's own
    per-call Request ID, which is the only part taken from the actual message."""
    request_id = (message or "").rsplit("Request ID: ", 1)[-1].split(";", 1)[0]
    return (
        "Studio does not exist. (Service: AWSEditors; Status Code: 400; "
        f"Error Code: InvalidRequestException; Request ID: {request_id}; Proxy: null)"
    )

CHECK = "op-studio-unknown-id-operations-fail"
GROUP = 'overly-permissive'
SERVICES = ['emr']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: every Studio read/mutate path must reject an unknown
    StudioId rather than inventing or silently accepting one."""
    emr = ctx.client("emr")
    bogus_studio = "es-" + "1234567890ABCDEFGHIJKLMNO"

    calls = {
        "DescribeStudio": lambda: emr.describe_studio(StudioId=bogus_studio),
        "UpdateStudio": lambda: emr.update_studio(StudioId=bogus_studio, Description="nope"),
        "DeleteStudio": lambda: emr.delete_studio(StudioId=bogus_studio),
    }
    for op, call in calls.items():
        code, message = _error(call)
        assert code == "InvalidRequestException", f"{op}: expected InvalidRequestException, got {code}"
        assert message == _studio_missing_message(message), f"{op}: unexpected message {message!r}"

    # ListStudios must simply not contain it (a list, not an error).
    studio_ids = {s["StudioId"] for s in emr.list_studios()["Studios"]}
    assert bogus_studio not in studio_ids, (
        f"ListStudios must not contain the never-created {bogus_studio!r}, saw {sorted(studio_ids)!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
