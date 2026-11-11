"""import-api-keys-invalid-format-rejected."""
from __future__ import annotations

import csv
import io
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-api-keys-invalid-format-rejected"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _rejection(fn) -> tuple[str, str]:
    """Call fn(); return the ClientError's (error code, message). Raises AssertionError if
    fn() succeeds. Deliberately does NOT catch
    ParamValidationError — that would mean the request never reached the
    service at all, which is not evidence about apigateway's own contract.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the operation to be rejected by the service, but it succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportApiKeys imports a well-formed one-row CSV (positive control) but rejects a binary
    non-CSV payload with BadRequestException, and an independent GetApiKeys shows the rejected
    call created no key."""
    ag = ctx.client("apigateway")

    control_name = ctx.unique_name("sim2real-behav-invalidfmt-control-")
    control_key = f"sim2realInvFmt{uuid.uuid4().hex}"[:40]
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["name", "key", "description", "enabled"])
    writer.writerow([control_name, control_key, "positive control", "TRUE"])
    good_body = buf.getvalue().encode("utf-8")

    control_result = ag.import_api_keys(body=good_body, format="csv")
    control_ids = control_result.get("ids") or []
    assert len(control_ids) == 1, (
        f"positive control: expected a well-formed CSV row to import exactly one key, got {control_result!r}"
    )
    control_id = control_ids[0]
    ctx.on_cleanup(lambda: _safe(lambda: ag.delete_api_key(apiKey=control_id)))

    # keys the rejected call could create are newer than the control key
    anchor = ag.get_api_key(apiKey=control_id)["createdDate"]

    garbage_body = bytes(range(256)) * 4  # arbitrary non-text, non-CSV binary payload
    code, message = _rejection(lambda: ag.import_api_keys(body=garbage_body, format="csv"))
    assert code == "BadRequestException", (
        f"expected a BadRequestException rejecting a garbage/unsupported ImportApiKeys payload, got {code!r}"
    )
    assert message == "Invalid API Key import content specified for format: csv", (
        f"unexpected rejection message {message!r}"
    )

    after = [k for page in ag.get_paginator("get_api_keys").paginate() for k in page.get("items", [])]
    # other checks' keys carry a sim2real- name; keys imported from the garbage body carry none
    created = [
        k["id"] for k in after
        if k["createdDate"] >= anchor and k["id"] != control_id
        and not (k.get("name") or "").startswith("sim2real-")
    ]
    assert created == [], f"a rejected ImportApiKeys must not create any keys, but found new ids {created}"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
