"""patch-replace-nonexistent-path-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ===== helpers =====
# _refusal normalizes the failure code and ALSO returns the
# human-readable diagnostic, because Cloud Control funnels every DesiredState/PatchDocument
# schema violation into one error code and the message is the only distinguishing detail.
# _properties is local: it decodes ResourceDescription.Properties, which Cloud Control returns
# as a JSON *string*.

TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}

HANDLER_ERROR_TO_EXCEPTION = {
    "AlreadyExists": "AlreadyExistsException",
    "NotFound": "ResourceNotFoundException",
    "NotUpdatable": "NotUpdatableException",
    "InvalidRequest": "InvalidRequestException",
    "ResourceConflict": "ResourceConflictException",
    "NotStabilized": "NotStabilizedException",
    "ServiceLimitExceeded": "ServiceLimitExceededException",
    "Throttling": "ThrottlingException",
    "AccessDenied": "AccessDeniedException",
    "InternalFailure": "HandlerInternalFailureException",
    "GeneralServiceException": "GeneralServiceException",
    "ServiceInternalError": "ServiceInternalErrorException",
    "NetworkFailure": "NetworkFailureException",
    "UnsupportedTarget": "UnsupportedActionException",
    "InvalidCredentials": "InvalidCredentialsException",
}


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_terminal(cc, request_token, timeout_s=90, interval_s=2):
    """Poll GetResourceRequestStatus until the request reaches a terminal OperationStatus."""
    holder = {}

    def probe():
        resp = cc.get_resource_request_status(RequestToken=request_token)
        holder["event"] = resp["ProgressEvent"]
        return holder["event"]

    _poll_until(
        probe,
        lambda e: e is not None and e.get("OperationStatus") in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description="request reaches a terminal OperationStatus",
    )
    return holder["event"]


def _delete_quiet(cc, type_name, identifier):
    """Teardown. DeleteResource is itself asynchronous, so poll the delete request to a terminal
    state rather than fire-and-forget."""
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=90, interval_s=2)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise


def _track(cc, ctx, type_name, identifier):
    ctx.on_cleanup(lambda: _delete_quiet(cc, type_name, identifier))


def _create_and_wait(cc, ctx, type_name, desired_state, track=True):
    resp = cc.create_resource(TypeName=type_name, DesiredState=desired_state)
    event = _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])
    if track and event.get("OperationStatus") == "SUCCESS":
        identifier = event.get("Identifier")
        if identifier:
            _track(cc, ctx, type_name, identifier)
    return event


def _update_and_wait(cc, type_name, identifier, patch_document):
    resp = cc.update_resource(
        TypeName=type_name, Identifier=identifier, PatchDocument=patch_document
    )
    return _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])


def _get_resource(cc, type_name, identifier):
    return cc.get_resource(TypeName=type_name, Identifier=identifier)


def _properties(cc, type_name, identifier):
    """GetResource returns Properties as a JSON *string* -- decode it before asserting."""
    resp = _get_resource(cc, type_name, identifier)
    assert resp["ResourceDescription"]["Identifier"] == identifier, resp
    return json.loads(resp["ResourceDescription"]["Properties"])


def _refusal(cc, call):
    """(code, diagnostic) for a mutating call expected to be refused, normalized across the two
    layers Cloud Control can refuse at: synchronously at the front door (ClientError) or
    asynchronously via a terminal FAILED ProgressEvent (ErrorCode + StatusMessage)."""
    try:
        resp = call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    event = _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])
    status = event.get("OperationStatus")
    assert status == "FAILED", (
        f"operation was expected to be refused but reached {status}: {event}"
    )
    handler_code = event.get("ErrorCode")
    return (
        HANDLER_ERROR_TO_EXCEPTION.get(handler_code, handler_code),
        event.get("StatusMessage") or "",
    )


def _ssm_desired_state(name, value="v1", ptype="String", **extra):
    """DesiredState is a JSON *string*, so it is built with json.dumps -- never a YAML library."""
    state = {"Name": name, "Type": ptype, "Value": value}
    state.update(extra)
    return json.dumps(state)


def _log_group_desired_state(name, **extra):
    """A log group with NO RetentionInDays, so /RetentionInDays is a valid-but-absent path.

    No log events are ever written, so the group costs nothing at rest even without a
    retention period.
    """
    state = {"LogGroupName": name}
    state.update(extra)
    return json.dumps(state)


def _patch(op, path, value):
    return json.dumps([{"op": op, "path": path, "value": value}])


CHECK = "patch-replace-nonexistent-path-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"
LOG_GROUP_TYPE = "AWS::Logs::LogGroup"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """JSON Patch "replace" on an absent path (/RetentionInDays) is refused, while "add" then "replace"
    on it succeed, so the refusal is about path absence; a write-only property's replace is a second
    refusal with its own message, so one catch-all diagnosis fails.
    """
    cc = ctx.client("cloudcontrol")
    group = ctx.unique_name("sim2real-behav-cc-loggroup-")

    # --- created deliberately WITHOUT RetentionInDays, so /RetentionInDays is absent.
    created = _create_and_wait(cc, ctx, LOG_GROUP_TYPE, _log_group_desired_state(group))
    assert created["OperationStatus"] == "SUCCESS", f"setup create failed: {created}"
    props = _properties(cc, LOG_GROUP_TYPE, group)
    assert "RetentionInDays" not in props, (
        f"precondition: the log group must start with no retention period: {props}"
    )

    # --- break exactly one thing: replace a path that is not in the current state.
    code, diagnostic = _refusal(
        cc,
        lambda: cc.update_resource(
            TypeName=LOG_GROUP_TYPE, Identifier=group,
            PatchDocument=_patch("replace", "/RetentionInDays", 7),
        ),
    )
    assert code == "ValidationException", (
        f"replace against an absent path must be refused with ValidationException, "
        f"got {code}: {diagnostic}"
    )
    assert diagnostic == (
        "[REPLACE Operation] noSuchPath in source, path provided : //RetentionInDays"
    ), (
        f"the refusal must name the operation AND the missing path, so it is "
        f"distinguishable from the write-only refusal asserted below; got {diagnostic!r}"
    )

    # effect-absent leg: the property must NOT have been created by the refused replace.
    props = _properties(cc, LOG_GROUP_TYPE, group)
    assert "RetentionInDays" not in props, (
        f"a refused replace upserted the property anyway: {props}"
    )
    assert props.get("LogGroupName") == group, (
        f"unrelated properties must be untouched: {props}"
    )

    # --- control 1: "add" against the same absent path is the operation that IS allowed to
    # create it, and the created value is readable.
    updated = _update_and_wait(
        cc, LOG_GROUP_TYPE, group, _patch("add", "/RetentionInDays", 7)
    )
    assert updated["OperationStatus"] == "SUCCESS", f"control add-patch must succeed: {updated}"
    props = _properties(cc, LOG_GROUP_TYPE, group)
    assert props.get("RetentionInDays") == 7, (
        f"add must create the absent path: {props}"
    )

    # --- control 2: the SAME replace that was refused above now succeeds, because the path
    # exists. Without this leg an emulator that refuses every `replace` would pass.
    replaced = _update_and_wait(
        cc, LOG_GROUP_TYPE, group, _patch("replace", "/RetentionInDays", 14)
    )
    assert replaced["OperationStatus"] == "SUCCESS", (
        f"replace on a path that now EXISTS must succeed -- the earlier refusal was about "
        f"the path being absent, not about replace being unsupported: {replaced}"
    )
    props = _properties(cc, LOG_GROUP_TYPE, group)
    assert props.get("RetentionInDays") == 14, (
        f"the accepted replace did not take effect: {props}"
    )

    # --- second negative, a NEIGHBOURING rule with the same error code and a different
    # message: a write-only property may only ever be `add`ed, absent or not.
    name = ctx.unique_name("sim2real-behav-cc-param-")
    param = _create_and_wait(cc, ctx, SSM_PARAM_TYPE, _ssm_desired_state(name, value="v1"))
    assert param["OperationStatus"] == "SUCCESS", f"setup create failed: {param}"
    write_only_message = (
        "Invalid patch update: writeOnlyProperties [/Description] can only be updated "
        "using 'add' operation"
    )
    code, diagnostic = _refusal(
        cc,
        lambda: cc.update_resource(
            TypeName=SSM_PARAM_TYPE, Identifier=name,
            PatchDocument=_patch("replace", "/Description", "sim2real-replace-write-only"),
        ),
    )
    assert code == "ValidationException", (
        f"replace against a write-only property must be refused, got {code}: {diagnostic}"
    )
    assert diagnostic == write_only_message, (
        f"the write-only refusal must be reported as such -- an emulator that answers with "
        f"the noSuchPath diagnosis instead tells the caller to fix the wrong thing; "
        f"expected {write_only_message!r}, got {diagnostic!r}"
    )
    props = _properties(cc, SSM_PARAM_TYPE, name)
    assert props.get("Value") == "v1", f"unrelated properties must be untouched: {props}"

    # ... and the write-only rule is genuinely about write-only-ness, not path absence: the
    # identical replace is refused with the identical message AFTER an `add` has set it.
    added = _update_and_wait(
        cc, SSM_PARAM_TYPE, name,
        _patch("add", "/Description", "sim2real-add-creates-the-path"),
    )
    assert added["OperationStatus"] == "SUCCESS", f"add of a write-only property: {added}"
    code, diagnostic = _refusal(
        cc,
        lambda: cc.update_resource(
            TypeName=SSM_PARAM_TYPE, Identifier=name,
            PatchDocument=_patch("replace", "/Description", "sim2real-second-replace"),
        ),
    )
    assert code == "ValidationException", (
        f"replace on a write-only property that now HAS a value must still be refused, "
        f"got {code}: {diagnostic}"
    )
    assert diagnostic == write_only_message, (
        f"the write-only refusal must not degrade into the absent-path one once the "
        f"property has been set; got {diagnostic!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
