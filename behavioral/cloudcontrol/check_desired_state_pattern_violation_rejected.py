"""desired-state-pattern-violation-rejected."""
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


def _get_resource(cc, type_name, identifier):
    return cc.get_resource(TypeName=type_name, Identifier=identifier)


def _properties(cc, type_name, identifier):
    """GetResource returns Properties as a JSON *string* -- decode it before asserting."""
    resp = _get_resource(cc, type_name, identifier)
    assert resp["ResourceDescription"]["Identifier"] == identifier, resp
    return json.loads(resp["ResourceDescription"]["Properties"])


def _error(fn):
    """(code, message) for a read expected to be refused. The messages Cloud Control returns
    for a refused read embed a RequestId and a RequestToken, so callers assert on the stable
    fragments rather than the whole string. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


def _list_identifiers(cc, type_name):
    """Every identifier of a type in this account/region, via the paginated ListResources."""
    identifiers = []
    for page in cc.get_paginator("list_resources").paginate(TypeName=type_name):
        identifiers += [d["Identifier"] for d in page.get("ResourceDescriptions", [])]
    return identifiers


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


def _log_group_desired_state(name):
    """RetentionInDays=1 is the cheapest retention; no log events are ever written, so the group
    costs nothing at rest."""
    return json.dumps({"LogGroupName": name, "RetentionInDays": 1})


CHECK = "desired-state-pattern-violation-rejected"
GROUP = 'error-semantics'
SERVICES = ['cloudcontrol']
LOG_GROUP_TYPE = "AWS::Logs::LogGroup"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DesiredState LogGroupName violating the schema's pattern (a colon) is refused, the same name
    without it succeeds, and the illegal name is absent from a ListResources proven non-vacuous;
    GetResource on it answers InvalidRequestException, a legal never-created name NotFound.
    """
    cc = ctx.client("cloudcontrol")
    base = ctx.unique_name("sim2real-behav-cc-loggroup-")
    illegal = base + ":colon-not-allowed"

    bad_state = _log_group_desired_state(illegal)
    code, diagnostic = _refusal(
        cc, lambda: cc.create_resource(TypeName=LOG_GROUP_TYPE, DesiredState=bad_state)
    )
    assert code == "ValidationException", (
        f"a pattern-violating DesiredState value must be refused with ValidationException, "
        f"got {code}: {diagnostic}"
    )
    # The front-door refusal is against the registry schema, and it names both the offending
    # property and the schema KEYWORD it violated -- which is what distinguishes this refusal
    # from the sibling additionalProperties / type / enum ones.
    assert diagnostic == (
        "Model validation failed (#/LogGroupName: failed validation constraint for keyword "
        "[pattern])"
    ), (
        f"the refusal must name the pattern-constrained property and the keyword, got "
        f"{diagnostic!r}"
    )

    # The illegal identifier is not merely absent -- it is unreadable, because the read
    # handler forwards it to CloudWatch Logs as a prefix and Logs applies the same character
    # class (see the docstring).
    # message varies: it embeds the CloudWatch Logs Request ID and the handler's own per-call
    # RequestToken, neither of which the check ever sees, so the stable fragments are asserted
    read_code, read_message = _error(lambda: _get_resource(cc, LOG_GROUP_TYPE, illegal))
    assert read_code == "InvalidRequestException", (
        f"GetResource for a pattern-violating identifier is refused, not reported absent; "
        f"got {read_code}: {read_message!r}"
    )
    for fragment in (
        "AWS::Logs::LogGroup Handler returned status FAILED",
        "logGroupNamePrefix",
        "(HandlerErrorCode: InvalidRequest",
    ):
        assert fragment in read_message, (
            f"the refused read must surface the handler's own diagnosis; {fragment!r} is "
            f"missing from {read_message!r}"
        )

    # A legal identifier that was never created DOES report absence, so the refusal above is
    # about the identifier's shape and not about existence.
    # message varies: the handler embeds its own per-call RequestToken, which the check never
    # sees, so the stable handler-code fragment is asserted
    nf_code, nf_message = _error(
        lambda: _get_resource(cc, LOG_GROUP_TYPE, base + "-never-created")
    )
    assert nf_code == "ResourceNotFoundException", (
        f"a legal-but-absent identifier must report absence, got {nf_code}: {nf_message!r}"
    )
    assert "(HandlerErrorCode: NotFound" in nf_message, (
        f"the not-found refusal must carry the NotFound handler code, got {nf_message!r}"
    )

    # Effect absent: the refused create provisioned nothing. ListResources is the only read
    # that can see a name of any shape, so it is the channel used here.
    before = _list_identifiers(cc, LOG_GROUP_TYPE)
    assert illegal not in before, (
        f"a refused create must leave no resource behind, but {illegal!r} is listed"
    )
    assert base not in before, (
        f"precondition: the control name must not exist yet, but {base!r} is listed"
    )

    # control: the same name without the illegal character succeeds.
    good = _create_and_wait(cc, ctx, LOG_GROUP_TYPE, _log_group_desired_state(base))
    assert good["OperationStatus"] == "SUCCESS", f"control create must succeed: {good}"
    props = _properties(cc, LOG_GROUP_TYPE, base)
    assert props.get("LogGroupName") == base, f"control resource has the wrong name: {props}"

    # ... and ListResources does report the control name, which is what makes the
    # effect-absent assertion above non-vacuous.
    after = _poll_until(
        lambda: _list_identifiers(cc, LOG_GROUP_TYPE),
        lambda idents: base in idents,
        timeout_s=60,
        interval_s=3.0,
        description="ListResources reports the created control log group",
    )
    assert illegal not in after, (
        f"the illegal name appeared after the control create: {illegal!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
