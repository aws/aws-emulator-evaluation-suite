"""failed-request-progress-event-carries-error-code-and-status-message."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}

# The HandlerErrorCode enum from the cloudcontrol Smithy model; used only to make an unexpected
# ErrorCode legible in the failure message.
MODELED_HANDLER_ERROR_CODES = (
    "NotUpdatable", "InvalidRequest", "AccessDenied", "UnauthorizedTaggingOperation",
    "InvalidCredentials", "AlreadyExists", "NotFound", "ResourceConflict", "Throttling",
    "ServiceLimitExceeded", "NotStabilized", "GeneralServiceException",
    "ServiceInternalError", "ServiceTimeout", "NetworkFailure", "InternalFailure",
)


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


def _track(cc, ctx, type_name, identifier, teardown):
    ctx.on_cleanup(lambda: _delete_resource(cc, type_name, identifier, teardown))


def _create_and_wait(cc, ctx, type_name, desired_state, track=True, *, teardown):
    resp = cc.create_resource(TypeName=type_name, DesiredState=desired_state)
    event = _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])
    if track and event.get("OperationStatus") == "SUCCESS":
        identifier = event.get("Identifier")
        if identifier:
            _track(cc, ctx, type_name, identifier, teardown)
    return event


def _get_resource(cc, type_name, identifier):
    return cc.get_resource(TypeName=type_name, Identifier=identifier)


def _properties(cc, type_name, identifier):
    """GetResource returns Properties as a JSON *string* -- decode it before asserting."""
    resp = _get_resource(cc, type_name, identifier)
    assert resp["ResourceDescription"]["Identifier"] == identifier, resp
    return json.loads(resp["ResourceDescription"]["Properties"])


def _error_code(fn):
    """The AWS error code and message raised by fn(). Raises if the call unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


#: A RequestToken: a lowercase UUID.
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _handler_not_found(message, detail):
    """The handler's NotFound text; its RequestToken (a UUID) is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    token = token if re.fullmatch(_UUID, token) else "<a UUID>"
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"


def _ssm_desired_state(name, value="v1", ptype="String", **extra):
    """DesiredState is a JSON *string*, so it is built with json.dumps -- never a YAML library."""
    state = {"Name": name, "Type": ptype, "Value": value}
    state.update(extra)
    return json.dumps(state)


CHECK = "failed-request-progress-event-carries-error-code-and-status-message"
GROUP = 'error-semantics'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A schema-valid request the owning service refuses fails asynchronously: FAILED with
    ErrorCode GeneralServiceException and a StatusMessage naming only the downstream operation.
    A SUCCESS terminal event carries neither member.

    Reference: https://docs.aws.amazon.com/cloudcontrolapi/latest/APIReference/API_ProgressEvent.html
    """
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()
    name = ctx.unique_name("sim2real-behav-cc-param-")

    failing_state = _ssm_desired_state(
        name, value="not-a-number", AllowedPattern="^[0-9]+$", Tags={"sim2real": CHECK}
    )
    resp = cc.create_resource(TypeName=SSM_PARAM_TYPE, DesiredState=failing_state)
    event = resp["ProgressEvent"]
    token = event["RequestToken"]
    # Schema-valid by construction: only SSM knows Value must satisfy AllowedPattern, so the
    # request is accepted and the failure is asynchronous.
    assert event["OperationStatus"] in ("PENDING", "IN_PROGRESS"), (
        f"a schema-valid request must be accepted before the handler runs, got {event}"
    )
    assert event["Operation"] == "CREATE", event

    terminal = _wait_terminal(cc, token)
    assert terminal["OperationStatus"] == "FAILED", (
        f"a handler refusal must drive the request to FAILED, got {terminal}"
    )
    assert terminal["Operation"] == "CREATE", terminal
    assert terminal["Identifier"] == name, terminal
    assert terminal["TypeName"] == SSM_PARAM_TYPE, terminal

    assert terminal.get("ErrorCode") in MODELED_HANDLER_ERROR_CODES, (
        f"a failed request must carry a modeled HandlerErrorCode; got "
        f"{terminal.get('ErrorCode')!r}, modeled values are {MODELED_HANDLER_ERROR_CODES}"
    )
    # Cloud Control does not translate the downstream refusal: an input error by SSM is reported
    # under the catch-all code, not InvalidRequest.
    assert terminal.get("ErrorCode") == "GeneralServiceException", (
        f"a downstream input refusal surfaces as GeneralServiceException; got "
        f"{terminal.get('ErrorCode')!r}"
    )
    status_message = terminal.get("StatusMessage") or ""
    assert status_message.strip(), (
        f"a failed request must explain itself in StatusMessage, got {status_message!r}"
    )
    # The message names the downstream OPERATION and nothing else -- SSM's own explanation of
    # the AllowedPattern violation is not carried through.
    assert status_message == "Error occurred during operation 'PutParameter'.", (
        f"StatusMessage must name the downstream operation that failed, got "
        f"{status_message!r}"
    )

    # the terminal record is immutable and re-readable, not consumed by the first read
    reread = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
    assert reread["OperationStatus"] == "FAILED", reread
    assert reread.get("ErrorCode") == terminal.get("ErrorCode"), (
        f"the terminal record must be stable across reads: {reread} vs {terminal}"
    )

    absent, absent_message = _error_code(lambda: _get_resource(cc, SSM_PARAM_TYPE, name))
    assert absent == "ResourceNotFoundException", (
        f"a FAILED create must leave no resource behind, got {absent}"
    )
    expected = _handler_not_found(
        absent_message,
        f"{SSM_PARAM_TYPE} Handler returned status FAILED: Resource of type '{SSM_PARAM_TYPE}' "
        f"with identifier '{name}' was not found.",
    )
    assert absent_message == expected, f"expected message {expected!r}, got {absent_message!r}"

    # control: the same AllowedPattern with a conforming Value succeeds, so the failure was the
    # value violating the pattern and not the AllowedPattern property itself.
    good = _create_and_wait(
        cc, ctx, SSM_PARAM_TYPE,
        _ssm_desired_state(name, value="12345", AllowedPattern="^[0-9]+$", Tags={"sim2real": CHECK}), teardown=teardown,
    )
    assert good["OperationStatus"] == "SUCCESS", f"control create must succeed: {good}"
    props = _properties(cc, SSM_PARAM_TYPE, name)
    assert props.get("Value") == "12345", f"control resource has the wrong value: {props}"

    # the diagnostic pair belongs to FAILURE only: a SUCCESS terminal event omits both members
    # entirely, so ErrorCode/StatusMessage cannot be read as always-present decoration.
    assert "ErrorCode" not in good, (
        f"a SUCCESS terminal event must carry no ErrorCode, got {good.get('ErrorCode')!r}"
    )
    assert "StatusMessage" not in good, (
        f"a SUCCESS terminal event must carry no StatusMessage, got "
        f"{good.get('StatusMessage')!r}"
    )


#: Seconds every teardown of one run shares: the suite's 900 s cleanup budget less a 120 s margin.
_CLEANUP_S = 780.0


class _Teardown:
    """One deadline for all of a run's teardowns, started when the first of them runs."""

    def __init__(self) -> None:
        self._at = None

    def deadline(self) -> float:
        if self._at is None:
            self._at = time.monotonic() + _CLEANUP_S
        return self._at


def _request_outcome(cc, token: str, teardown) -> dict:
    """Poll GetResourceRequestStatus every 2 s until the request ends; return its ProgressEvent."""
    while True:
        event = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if event["OperationStatus"] not in ("PENDING", "IN_PROGRESS", "CANCEL_IN_PROGRESS"):
            return event
        if time.monotonic() >= teardown.deadline():
            raise AssertionError(
                f"request {token} is still {event['OperationStatus']} at the cleanup deadline"
            )
        time.sleep(2)


def _delete_resource(cc, type_name: str, identifier: str, teardown) -> None:
    """DeleteResource and wait for its outcome; a NotFound answer means the resource is gone.

    ConcurrentOperationException and ResourceConflictException (another request holds the
    resource) are retried every 2 s to the shared cleanup deadline; anything else raises."""
    while True:
        try:
            resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConcurrentOperationException", "ResourceConflictException"):
                raise
            if time.monotonic() >= teardown.deadline():
                raise
            time.sleep(2)
    event = _request_outcome(cc, resp["ProgressEvent"]["RequestToken"], teardown)
    if event["OperationStatus"] == "FAILED" and event.get("ErrorCode") == "NotFound":
        return
    if event["OperationStatus"] != "SUCCESS":
        raise AssertionError(
            f"DeleteResource of {type_name} {identifier} ended {event['OperationStatus']}: {event}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
