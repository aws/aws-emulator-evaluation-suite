"""change-calendar-state-and-multi-calendar-intersection."""
from __future__ import annotations

import datetime as dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-calendar-state-and-multi-calendar-intersection"
GROUP = 'state-machine'
SERVICES = ['ssm']

# Fixed far-future closed windows, so every assertion below is deterministic and
# independent of when the check runs.
#   calendar A: CLOSED 2030-01-06 00:00Z .. 12:00Z
#   calendar B: CLOSED 2030-01-07 00:00Z .. 12:00Z
_A_START, _A_END = "20300106T000000Z", "20300106T120000Z"
_B_START, _B_END = "20300107T000000Z", "20300107T120000Z"


def _calendar_content(uid, dtstart, dtend, description):
    """A DEFAULT_OPEN Change Calendar: open everywhere except inside its VEVENTs."""
    return "\n".join(
        [
            "BEGIN:VCALENDAR",
            "PRODID:-//AWS//Change Calendar 1.0//EN",
            "VERSION:2.0",
            "X-CALENDAR-TYPE:DEFAULT_OPEN",
            f"X-WR-CALDESC:{description}",
            "BEGIN:VEVENT",
            "DTSTAMP:20260101T000000Z",
            f"DTSTART:{dtstart}",
            f"DTEND:{dtend}",
            f"UID:{uid}",
            f"SUMMARY:{description}",
            "END:VEVENT",
            "END:VCALENDAR",
        ]
    )


def _error_code(fn):
    """Return the ClientError (code, message) raised by fn; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, timeout_s=120, interval_s=3.0):
    """Poll until predicate holds: a new document is Creating before Active, and
    GetCalendarState refuses a non-Active calendar."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _parse_iso(value):
    """Parse GetCalendarState's ISO8601 string fields (botocore does not parse them)."""
    assert isinstance(value, str) and value, f"expected an ISO8601 string, got {value!r}"
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                parsed = dt.datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            raise AssertionError(f"unparseable ISO8601 timestamp: {value!r}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _utc(year, month, day, hour=0, minute=0):
    return dt.datetime(year, month, day, hour, minute, tzinfo=dt.timezone.utc)


def _at(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetCalendarState evaluates a DEFAULT_OPEN calendar to OPEN/CLOSED at AtTime with the exact
    NextTransitionTime, CLOSES a set when any member is closed, and refuses invalid members.
    """

    ssm = ctx.client("ssm")

    cal_a = ctx.unique_name("sim2real-behav-cal-a-")
    cal_b = ctx.unique_name("sim2real-behav-cal-b-")

    ssm.create_document(
        Name=cal_a,
        DocumentType="ChangeCalendar",
        # VCALENDAR content is plain text; omitting DocumentFormat defaults to JSON
        # and the create fails with InvalidDocumentContent.
        DocumentFormat="TEXT",
        Content=_calendar_content(
            "sim2real-behav-cal-a-event", _A_START, _A_END, "sim2real-behav closed A"
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=cal_a, Force=True))

    ssm.create_document(
        Name=cal_b,
        DocumentType="ChangeCalendar",
        DocumentFormat="TEXT",
        Content=_calendar_content(
            "sim2real-behav-cal-b-event", _B_START, _B_END, "sim2real-behav closed B"
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=cal_b, Force=True))

    for name in (cal_a, cal_b):
        described = _poll(
            lambda n=name: ssm.describe_document(Name=n)["Document"],
            lambda d: d.get("Status") == "Active",
        )
        assert described["DocumentType"] == "ChangeCalendar", described
        assert described["DocumentFormat"] == "TEXT", described

    # --- single calendar: inside its closed window ---------------------------
    inside_a = _at(_utc(2030, 1, 6, 6))
    state = ssm.get_calendar_state(CalendarNames=[cal_a], AtTime=inside_a)
    assert state["State"] == "CLOSED", (
        f"{inside_a} falls inside calendar A's VEVENT and must be CLOSED, got {state}"
    )
    assert _parse_iso(state["AtTime"]) == _utc(2030, 1, 6, 6), (
        f"GetCalendarState must echo the requested AtTime, got {state['AtTime']!r}"
    )
    assert _parse_iso(state["NextTransitionTime"]) == _utc(2030, 1, 6, 12), (
        "the next transition out of A's closed window is 2030-01-06T12:00:00Z, got "
        f"{state['NextTransitionTime']!r}"
    )

    # --- single calendar: before the closed window --------------------------
    before_a = _at(_utc(2030, 1, 5))
    state = ssm.get_calendar_state(CalendarNames=[cal_a], AtTime=before_a)
    assert state["State"] == "OPEN", (
        f"a DEFAULT_OPEN calendar must be OPEN outside its VEVENTs, got {state}"
    )
    assert _parse_iso(state["NextTransitionTime"]) == _utc(2030, 1, 6, 0), (
        "the next transition into A's closed window is 2030-01-06T00:00:00Z, got "
        f"{state['NextTransitionTime']!r}"
    )

    # Boundary semantics: DTSTART is inclusive, DTEND is exclusive.
    assert (
        ssm.get_calendar_state(CalendarNames=[cal_a], AtTime=_at(_utc(2030, 1, 6, 0)))[
            "State"
        ]
        == "CLOSED"
    ), "DTSTART is inclusive: 2030-01-06T00:00:00Z must be CLOSED"
    assert (
        ssm.get_calendar_state(CalendarNames=[cal_a], AtTime=_at(_utc(2030, 1, 6, 12)))[
            "State"
        ]
        == "OPEN"
    ), "DTEND is exclusive: 2030-01-06T12:00:00Z must already be OPEN"

    # --- intersection: CLOSED in any one calendar closes the set ------------
    # At 2030-01-06T06:00Z A is CLOSED and B is OPEN.
    assert (
        ssm.get_calendar_state(CalendarNames=[cal_b], AtTime=inside_a)["State"] == "OPEN"
    ), "calendar B alone must be OPEN at 2030-01-06T06:00:00Z (its window is the 7th)"
    both_a = ssm.get_calendar_state(CalendarNames=[cal_a, cal_b], AtTime=inside_a)
    assert both_a["State"] == "CLOSED", (
        "a calendar set is CLOSED when ANY member is CLOSED; A is closed and B is open "
        f"at {inside_a}, got {both_a}"
    )

    # ...and symmetrically on B's day, where A is the open one.
    inside_b = _at(_utc(2030, 1, 7, 6))
    assert (
        ssm.get_calendar_state(CalendarNames=[cal_a], AtTime=inside_b)["State"] == "OPEN"
    ), "calendar A alone must be OPEN at 2030-01-07T06:00:00Z"
    both_b = ssm.get_calendar_state(CalendarNames=[cal_a, cal_b], AtTime=inside_b)
    assert both_b["State"] == "CLOSED", (
        f"the set must be CLOSED at {inside_b} because B is closed, got {both_b}"
    )
    # Order of CalendarNames must not change the answer.
    assert (
        ssm.get_calendar_state(CalendarNames=[cal_b, cal_a], AtTime=inside_b)["State"]
        == "CLOSED"
    ), "the intersection must be order-independent"

    # --- both open: the set is OPEN, and the next transition is the nearest --
    both_open = ssm.get_calendar_state(
        CalendarNames=[cal_a, cal_b], AtTime=_at(_utc(2030, 1, 5))
    )
    assert both_open["State"] == "OPEN", (
        f"both calendars are open on 2030-01-05, got {both_open}"
    )
    assert _parse_iso(both_open["NextTransitionTime"]) == _utc(2030, 1, 6, 0), (
        "the set's next transition is the EARLIEST member transition "
        f"(2030-01-06T00:00:00Z), got {both_open['NextTransitionTime']!r}"
    )

    # --- negatives: the op must refuse non-calendars and unknown documents ---
    plain = ctx.unique_name("sim2real-behav-notcal-")
    ssm.create_document(
        Name=plain,
        DocumentType="Command",
        DocumentFormat="JSON",
        Content=(
            '{"schemaVersion":"2.2","description":"sim2real-behav not a calendar",'
            '"mainSteps":[{"action":"aws:runShellScript","name":"noop",'
            '"inputs":{"runCommand":["true"]}}]}'
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=plain, Force=True))
    _poll(
        lambda: ssm.describe_document(Name=plain)["Document"],
        lambda d: d.get("Status") == "Active",
    )
    not_a_calendar = (
        "InvalidDocumentType",
        f"A document exists with the name '{plain}', but it is not of type 'ChangeCalendar'.",
    )
    wrong_type = _error_code(
        lambda: ssm.get_calendar_state(CalendarNames=[plain], AtTime=inside_a)
    )
    assert wrong_type == not_a_calendar, (
        f"GetCalendarState on a Command document must be refused with {not_a_calendar!r}, "
        f"got {wrong_type!r}"
    )
    unknown = _error_code(
        lambda: ssm.get_calendar_state(
            CalendarNames=["sim2real-behav-no-such-calendar"], AtTime=inside_a
        )
    )
    expected_unknown = (
        "InvalidDocument",
        "The specified Change Calendar Document 'sim2real-behav-no-such-calendar' does not exist.",
    )
    assert unknown == expected_unknown, (
        f"an unknown calendar name must be refused with {expected_unknown!r}, got {unknown!r}"
    )
    # A mixed set must fail closed rather than silently answer from the valid member.
    mixed = _error_code(
        lambda: ssm.get_calendar_state(CalendarNames=[cal_a, plain], AtTime=inside_a)
    )
    assert mixed == not_a_calendar, (
        "one invalid member must fail the whole GetCalendarState call, not be ignored; "
        f"got {mixed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
