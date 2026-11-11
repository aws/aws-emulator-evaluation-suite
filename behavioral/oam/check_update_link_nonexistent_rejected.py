"""update-link-nonexistent-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-link-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["oam"]
_NOT_FOUND = "Resource not found."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """UpdateLink on a well-formed nonexistent link ARN fails with AccessDeniedException, while GetLink
    and DeleteLink on it fail with ResourceNotFoundException, each with the exact message; a created
    sink reads back by GetSink."""
    oam = ctx.client("oam")
    account_id = _own_account_id(ctx)
    region = ctx.region

    bogus_arn = f"arn:aws:oam:{region}:{account_id}:link/{uuid.uuid4()}"
    code, code_message = _error(
        lambda: oam.update_link(Identifier=bogus_arn, ResourceTypes=["AWS::CloudWatch::Metric"])
    )
    assert code == "AccessDeniedException", f"got {code!r}"
    assert code_message == _explicit_deny_message(ctx, "UpdateLink", f"arn:aws:oam:{region}:{account_id}:link/*"), f"got message {code_message!r}"

    # consistency control: GetLink (read-only) on the same nonexistent identifier reports it is
    # absent via the service's own NotFound, not the mutating-call access-control path above.
    get_code, get_code_message = _error(lambda: oam.get_link(Identifier=bogus_arn))
    assert get_code == "ResourceNotFoundException", f"got {get_code!r}"
    assert get_code_message == _NOT_FOUND, f"got message {get_code_message!r}"
    delete_code, delete_code_message = _error(lambda: oam.delete_link(Identifier=bogus_arn))
    assert delete_code == "ResourceNotFoundException", f"got {delete_code!r}"
    assert delete_code_message == _NOT_FOUND, f"got message {delete_code_message!r}"

    # positive control: a real sink can still be created/managed -- proves the account/region
    # is otherwise healthy and the rejection above is specific to the nonexistent link identity.
    sink_name = ctx.unique_name("sim2real-oam-sink-")
    sink = _create_sink_retrying(oam, sink_name)
    sink_arn = sink["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, sink_arn))
    oam.tag_resource(ResourceArn=sink_arn, Tags={"sim2real": "true"})
    assert sink["Name"] == sink_name

    # terminal assertion is an independent read at the destination (GetSink), not an echo of
    # the CreateSink response above.
    fetched = oam.get_sink(Identifier=sink_arn)
    assert fetched["Name"] == sink_name, f"got {fetched.get('Name')!r}"


def _explicit_deny_message(ctx, action, resource):
    caller = ctx.client("sts").get_caller_identity()["Arn"]
    return (
        f"User: {caller} is not authorized to perform: oam:{action} on resource: {resource} "
        "with an explicit deny in a resource-based policy"
    )


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _own_account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_sink_retrying(oam, name, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return oam.create_sink(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ServiceQuotaExceededException":
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _delete_sink_ignore_missing(oam, arn):
    try:
        oam.delete_sink(Identifier=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
