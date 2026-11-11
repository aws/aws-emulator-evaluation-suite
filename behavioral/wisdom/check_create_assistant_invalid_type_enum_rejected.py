"""create-assistant-invalid-type-enum-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-assistant-invalid-type-enum-rejected"
GROUP = "overly-permissive"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAssistant with a type value outside the AssistantType enum (only AGENT is valid)
    must be rejected with BadRequestException, no assistant must be created for that name, and
    the same call with type=AGENT (positive control) must succeed."""
    wisdom = ctx.client("wisdom")
    bad_name = ctx.unique_name("sim2real-behav-badtype-")

    # break exactly one thing: an invalid AssistantType value
    code, message = _error(lambda: wisdom.create_assistant(name=bad_name, type="NOT_A_REAL_ASSISTANT_TYPE"))
    assert code == "BadRequestException", f"code={code}"
    assert message == "Invalid request body", f"expected the invalid-request-body message, got {message!r}"

    # effect absent: no assistant with this name exists
    listed = _list_all_assistants(wisdom)
    assert bad_name not in [a["name"] for a in listed], f"bad_name={bad_name!r} leaked into list_assistants"

    # positive control: the valid enum value succeeds
    good_name = ctx.unique_name("sim2real-behav-goodtype-")
    created = wisdom.create_assistant(
        name=good_name, type="AGENT", tags={"sim2real-behav": "1"}
    )["assistant"]
    assistant_id = created["assistantId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_assistant(assistantId=assistant_id)))

    # terminal read: independent of the mutating call, at the destination
    reread = wisdom.get_assistant(assistantId=assistant_id)["assistant"]
    assert reread["type"] == "AGENT", f"expected type=AGENT on independent read, got {reread['type']!r}"


def _safe_delete(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _list_all_assistants(wisdom):
    out = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = wisdom.list_assistants(**kwargs)
        out.extend(resp.get("assistantSummaries", []))
        token = resp.get("nextToken")
        if not token:
            break
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
