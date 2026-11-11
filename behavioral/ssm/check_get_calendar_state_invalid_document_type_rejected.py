"""get-calendar-state-invalid-document-type-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-calendar-state-invalid-document-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]

_CALENDAR_CONTENT = (
    "BEGIN:VCALENDAR\r\n"
    "PRODID:-//AWS//Change Calendar 1.0//EN\r\n"
    "VERSION:2.0\r\n"
    "X-CALENDAR-TYPE:DEFAULT_OPEN\r\n"
    "X-WR-CALDESC:sim2real test calendar\r\n"
    "BEGIN:VTODO\r\n"
    "DTSTAMP:20200320T004207Z\r\n"
    "UID:3b5af39a-d0b3-4049-a839-d7bb8af01f92\r\n"
    "SUMMARY:Add events to this calendar.\r\n"
    "END:VTODO\r\n"
    "END:VCALENDAR\r\n"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCalendarState against a document that is not of type ChangeCalendar is rejected with
    InvalidDocumentType, while a DEFAULT_OPEN ChangeCalendar document reports OPEN."""
    ssm = ctx.client("ssm")

    # positive control: a DEFAULT_OPEN ChangeCalendar with no events reports OPEN
    calendar_name = ctx.unique_name("sim2real-ssm-calendar-")
    ssm.create_document(
        Name=calendar_name,
        Content=_CALENDAR_CONTENT,
        DocumentType="ChangeCalendar",
        DocumentFormat="TEXT",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=calendar_name))
    control = ssm.get_calendar_state(CalendarNames=[calendar_name])
    assert control["State"] == "OPEN", (
        f"a DEFAULT_OPEN ChangeCalendar document with no events must report OPEN, got {control!r}"
    )

    # break exactly one thing: create a Command document and query it as a calendar
    command_name = ctx.unique_name("sim2real-ssm-notcalendar-")
    command_content = json.dumps(
        {
            "schemaVersion": "2.2",
            "description": "not a calendar",
            "mainSteps": [
                {
                    "action": "aws:runShellScript",
                    "name": "runShellScript",
                    "inputs": {"runCommand": ["echo sim2real-not-a-calendar"]},
                }
            ],
        }
    )
    ssm.create_document(
        Name=command_name,
        Content=command_content,
        DocumentType="Command",
        DocumentFormat="JSON",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=command_name))

    error = _error(lambda: ssm.get_calendar_state(CalendarNames=[command_name]))
    assert error["Code"] == "InvalidDocumentType", (
        f"GetCalendarState against a Command document must fail with InvalidDocumentType, got {error!r}"
    )
    assert error["Message"] == (
        f"A document exists with the name '{command_name}', but it is not of type 'ChangeCalendar'."
    ), error["Message"]


def _error(fn):
    """Return the ClientError error dict raised by fn. An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        f"real AWS rejects GetCalendarState on a non-calendar document, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
