"""filter-expression-operand-type-mismatch-rejected-on-both-surfaces."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-expression-operand-type-mismatch-rejected-on-both-surfaces"
GROUP = "overly-permissive"
SERVICES = ["xray"]

ERR_INVALID_REQUEST = "InvalidRequestException"

#: Well-typed, and using the very keywords the mismatched probes abuse: a number keyword compared
#: with a number, and a string keyword compared with a string operator.
CONTROL_EXPRESSION = 'responsetime > 5 AND http.url CONTAINS "/probe"'

#: Each entry breaks exactly ONE thing about the control: the TYPE of one operand. The third
#: element is the message AWS returns for it on both surfaces.
MISMATCHES = (
    (
        'responsetime > "abc"',
        "a NUMBER keyword given a non-numeric quoted operand",
        "You can't compare a non-numeric value of type [String] against property [responsetime] "
        "for the > operator.",
    ),
    (
        "http.url > 5",
        "a STRING keyword given a numeric comparison operator, which is not in its operator set",
        "You can't compare a non-numeric property [http.url] for the > operator.",
    ),
)


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A type-mismatched filter expression is refused with InvalidRequestException by both
    CreateGroup and GetTraceSummaries and leaves no group behind, while a well-typed control
    expression succeeds on both before and after.

    Reference: https://docs.aws.amazon.com/xray/latest/devguide/xray-console-filters.html
    """
    xr = ctx.client("xray")
    now = time.time()
    win_start, win_end = now - 600.0, now + 60.0

    control_group = ctx.unique_name("sim2real-bh-xft-")
    names_before = _group_names(xr)
    assert control_group not in names_before, (
        f"the freshly generated group name {control_group!r} already exists in this account"
    )
    created = xr.create_group(GroupName=control_group, FilterExpression=CONTROL_EXPRESSION,
                              Tags=[{"Key": "sim2real", "Value": "1"},
                                    {"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: xr.delete_group(GroupName=control_group))
    assert created["Group"]["FilterExpression"] == CONTROL_EXPRESSION, (
        f"the accepted group must store the well-typed expression verbatim; CreateGroup echoed "
        f"{created['Group'].get('FilterExpression')!r} for {CONTROL_EXPRESSION!r}"
    )
    stored = xr.get_group(GroupName=control_group)["Group"]
    assert stored["FilterExpression"] == CONTROL_EXPRESSION, (
        f"an independent GetGroup read must return the stored expression unchanged; it returned "
        f"{stored.get('FilterExpression')!r}"
    )
    _control_read_succeeds(xr, win_start, win_end, when="before the mismatched probes")

    probe_groups = set()
    for expression, why, expected_message in MISMATCHES:
        probe_group = ctx.unique_name("sim2real-bh-xfb-")
        probe_groups.add(probe_group)
        before = _group_names(xr)
        assert probe_group not in before, (
            f"the freshly generated group name {probe_group!r} already exists in this account"
        )
        try:
            accepted = xr.create_group(GroupName=probe_group, FilterExpression=expression)
        except ClientError as exc:
            err = exc.response["Error"]
            assert err["Code"] == ERR_INVALID_REQUEST, (
                f"CreateGroup must refuse {expression!r} ({why}) with {ERR_INVALID_REQUEST!r}; a "
                f"target that accepts it is promising a filter whose operand it cannot compare. "
                f"Got {err['Code']!r}: {err.get('Message')!r}"
            )
            assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, (
                f"a type-mismatched expression is a client error and must be a 400, not a 5xx or "
                f"a 200 with a verdict in the body; got "
                f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r} for {expression!r}"
            )
            assert err.get("Message") == expected_message, (
                f"CreateGroup must refuse {expression!r} with {expected_message!r}; got "
                f"{err.get('Message')!r}"
            )
        else:
            # Register teardown from THIS response before asserting: a lookup would lag the create
            # and the group must not leak just because the service should have refused it.
            ctx.on_cleanup(lambda name=probe_group: xr.delete_group(GroupName=name))
            raise AssertionError(
                f"CreateGroup ACCEPTED the type-mismatched expression {expression!r} ({why}); it "
                f"returned {accepted!r}"
            )

        after = _group_names(xr)
        assert probe_group not in after, (
            f"a refused CreateGroup still created the group {probe_group!r} for {expression!r}; "
            f"the new names were {sorted(after - before)}"
        )

        read_code, read_message = _error_code(lambda: xr.get_trace_summaries(
            StartTime=_utc(win_start), EndTime=_utc(win_end), FilterExpression=expression,
            Sampling=False))
        assert read_code == ERR_INVALID_REQUEST, (
            f"GetTraceSummaries must refuse the same expression CreateGroup refused "
            f"({expression!r}, {why}); otherwise an implementation validates on write and silently "
            f"matches nothing on read. Got {read_code!r}: {read_message!r}"
        )
        assert read_message == expected_message, (
            f"GetTraceSummaries must refuse {expression!r} with {expected_message!r}; got "
            f"{read_message!r}"
        )

    # A mismatched operand can never become well-typed, so instead of a restore leg the control
    # re-runs to show the refusals were about the operand type, not the account or credentials.
    still_stored = xr.get_group(GroupName=control_group)["Group"]
    assert still_stored["FilterExpression"] == CONTROL_EXPRESSION, (
        f"the control group's well-typed expression must be untouched by the refused calls; it "
        f"now reads {still_stored.get('FilterExpression')!r}"
    )
    _control_read_succeeds(xr, win_start, win_end, when="after the mismatched probes")

    final_names = _group_names(xr)
    assert control_group in final_names, (
        f"the accepted control group {control_group!r} must appear in the account's group list; "
        f"GetGroups returned {len(final_names)} names without it"
    )
    assert not (probe_groups & final_names), (
        f"no group named in a refused CreateGroup may appear in the account's group list; "
        f"GetGroups reported {sorted(probe_groups & final_names)}"
    )


def _utc(ts: float) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)


def _group_names(xr, max_pages=25):
    """Every group name in the account, following NextToken; raises rather than truncating."""
    names = set()
    token = None
    for _ in range(max_pages):
        page = xr.get_groups(**({"NextToken": token} if token else {}))
        names.update(g["GroupName"] for g in page["Groups"])
        token = page.get("NextToken")
        if not token:
            return names
    raise AssertionError(
        f"GetGroups still offered a NextToken after {max_pages} pages; the account holds too many "
        f"groups for the effect-absent assertion to be reliable"
    )


def _error_code(fn):
    """(code, message) for a call expected to be refused; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"the call was expected to be refused but succeeded, returning {result!r}"
    )


def _control_read_succeeds(xr, start_ts, end_ts, *, when):
    """Asserts GetTraceSummaries accepts the control expression; the returned traces are not
    checked because the account is shared."""
    resp = xr.get_trace_summaries(
        StartTime=_utc(start_ts), EndTime=_utc(end_ts),
        FilterExpression=CONTROL_EXPRESSION, Sampling=False,
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"the well-typed control expression {CONTROL_EXPRESSION!r} must be answered by "
        f"GetTraceSummaries {when}; got {resp['ResponseMetadata']!r}"
    )
    assert "TraceSummaries" in resp, (
        f"an accepted GetTraceSummaries must carry a TraceSummaries member {when}; the response "
        f"held {sorted(resp)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
