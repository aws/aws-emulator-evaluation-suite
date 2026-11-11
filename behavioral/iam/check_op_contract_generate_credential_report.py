"""op-contract-generateCredentialReport."""
from __future__ import annotations

import base64
import time
from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-generateCredentialReport"
GROUP = "error-semantics"
SERVICES = ["iam"]

_VALID_STATES = {"STARTED", "INPROGRESS", "COMPLETE"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GenerateCredentialReport answers a State of STARTED, INPROGRESS or COMPLETE (or
    LimitExceeded), an immediate GetCredentialReport returns the report or ReportInProgress
    with an empty message, and the finished report is text/csv with the documented header."""
    iam = ctx.client("iam")

    gen, gen_code, _ = _try(lambda: iam.generate_credential_report())
    if gen_code is not None:
        # LimitExceeded means a generation was already kicked off very recently
        # (e.g. by a concurrently running check) -- still a documented, specific
        # code, not a generic failure.
        # message not asserted: neither the API model nor the docs give LimitExceeded's wording.
        assert gen_code == "LimitExceeded", f"unexpected error code: {gen_code!r}"
        gen = None
    if gen is not None:
        assert gen.get("State") in _VALID_STATES, f"unexpected State: {gen.get('State')!r}"
        # Description is documented as optional (only "State" is required) --
        # real AWS omits it entirely when serving an already-COMPLETE cached
        # report, so only validate its type/non-emptiness when present at all.
        if "Description" in gen:
            assert isinstance(gen["Description"], str) and gen["Description"], (
                f"Description present but not a non-empty string: {gen['Description']!r}"
            )

    # Immediately probing the report must either return the (possibly cached)
    # completed report, or fail with exactly ReportInProgress -- no other code
    # is a valid response to a just-(re)started generation job.
    report, code, message = _try(lambda: iam.get_credential_report())
    if code is not None:
        # IAM's ReportInProgress carries an empty message.
        assert code == "ReportInProgress", f"unexpected error code: {code!r}"
        assert message == "", f"expected an empty ReportInProgress message, got {message!r}"

    # Poll to completion (bounded) and validate the final artifact end-to-end.
    # Bounded by the runner's remaining time, so a report that never converges fails here.
    budget_s = max(1.0, min(60.0, (ctx.time_left() or 60.0) - 5.0))
    deadline = time.monotonic() + budget_s
    while report is None and time.monotonic() < deadline:
        time.sleep(2.0)
        report, code, _ = _try(lambda: iam.get_credential_report())
        if code is not None and code != "ReportInProgress":
            raise AssertionError(f"unexpected error code while polling: {code!r}")

    assert report is not None, f"credential report never became available within {budget_s:.0f}s"
    assert report["ReportFormat"] == "text/csv", f"unexpected ReportFormat: {report['ReportFormat']!r}"
    # botocore blob members are already base64-decoded into raw bytes by the
    # time they reach the response dict -- decode straight to text. Fall back
    # to an explicit base64 decode only if a future/alternate botocore
    # version hands back the still-encoded string form.
    content = report["Content"]
    csv_text = content.decode("utf-8") if isinstance(content, bytes) else base64.b64decode(content).decode("utf-8")
    header = csv_text.splitlines()[0]
    assert header.startswith("user,arn,user_creation_time"), f"unexpected CSV header: {header!r}"


def _try(fn) -> tuple[Any, str | None, str | None]:
    from botocore.exceptions import ClientError

    try:
        return fn(), None, None
    except ClientError as exc:
        return None, exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
