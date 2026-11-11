"""list-contacts-invalid-time-window-rejected."""
from __future__ import annotations

import datetime as _dt

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-contacts-invalid-time-window-rejected"
GROUP = "overly-permissive"
SERVICES = ["groundstation"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(
        f"real AWS rejects a start-after-end time window, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListContacts rejects a request whose startTime is after its endTime, while the same
    call with a correctly-ordered window succeeds."""
    gs = ctx.client("groundstation")
    now = _dt.datetime.now(_dt.timezone.utc)

    good = gs.list_contacts(
        statusList=["COMPLETED"],
        startTime=now - _dt.timedelta(hours=1),
        endTime=now,
    )
    assert "contactList" in good, f"expected a contactList key in the response, got {good!r}"

    refused = _error(
        lambda: gs.list_contacts(
            statusList=["COMPLETED"],
            startTime=now,
            endTime=now - _dt.timedelta(hours=1),
        )
    )
    assert refused == (
        "InvalidParameterException",
        "Invalid request: End date must be after start date",
    ), f"expected InvalidParameterException for startTime > endTime, got {refused!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
