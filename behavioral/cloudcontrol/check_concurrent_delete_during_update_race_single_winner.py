"""concurrent-delete-during-update-race-single-winner."""
from __future__ import annotations

import concurrent.futures
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-delete-during-update-race-single-winner"
GROUP = "concurrency"
SERVICES = ["cloudcontrol"]

_TYPE_NAME = "AWS::SQS::Queue"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent DeleteResource and UpdateResource on one identifier: exactly one is accepted and
    reaches SUCCESS, the other is rejected with ConcurrentOperationException."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-cc-race-")

    resp = cc.create_resource(
        TypeName=_TYPE_NAME, DesiredState=json.dumps({"QueueName": name, "VisibilityTimeout": 30})
    )
    create_pe = _wait_for_terminal(cc, resp["ProgressEvent"]["RequestToken"])
    assert create_pe["OperationStatus"] == "SUCCESS", f"create did not succeed: {create_pe}"
    identifier = create_pe["Identifier"]
    ctx.on_cleanup(lambda: _cleanup_delete(cc, _TYPE_NAME, identifier))

    def do_update():
        return cc.update_resource(
            TypeName=_TYPE_NAME,
            Identifier=identifier,
            PatchDocument=json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 90}]),
        )

    def do_delete():
        return cc.delete_resource(TypeName=_TYPE_NAME, Identifier=identifier)

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        futures = {"update": ex.submit(do_update), "delete": ex.submit(do_delete)}
        for op_name, fut in futures.items():
            try:
                results[op_name] = ("ok", fut.result())
            except ClientError as e:
                results[op_name] = ("error", (e.response["Error"]["Code"], e.response["Error"]["Message"]))

    oks = [k for k, v in results.items() if v[0] == "ok"]
    errs = [k for k, v in results.items() if v[0] == "error"]
    assert len(oks) == 1 and len(errs) == 1, (
        f"expected exactly one accepted operation and one immediate rejection, got: {results}"
    )
    winner, loser = oks[0], errs[0]

    loser_code, loser_message = results[loser][1]
    assert loser_code == "ConcurrentOperationException", (
        f"expected the losing {loser} to be rejected with ConcurrentOperationException, "
        f"got {loser_code}"
    )

    winner_token = results[winner][1]["ProgressEvent"]["RequestToken"]
    # The loser names the winner's RequestToken only once the winner's request is registered, so
    # either exact form is AWS's answer depending on how close the two calls land.
    concurrent_message = f"Concurrent operation found for resource {identifier}"
    expected_loser = (concurrent_message, f"{concurrent_message} with RequestToken {winner_token}")
    assert loser_message in expected_loser, (
        f"expected the loser's message to be one of {expected_loser!r}, got {loser_message!r}"
    )
    winner_pe = _wait_for_terminal(cc, winner_token)
    assert winner_pe["OperationStatus"] == "SUCCESS", f"winning {winner} did not reach SUCCESS: {winner_pe}"

    if winner == "delete":
        code, message = _client_error(lambda: cc.get_resource(TypeName=_TYPE_NAME, Identifier=identifier))
        assert code == "ResourceNotFoundException", (
            f"expected the queue to be gone after the winning delete, got code={code}"
        )
        expected = _handler_not_found(_TYPE_NAME, identifier, message)
        assert message == expected, f"expected message {expected!r}, got {message!r}"
        mutate_code, mutate_message = _client_error(
            lambda: cc.update_resource(
                TypeName=_TYPE_NAME,
                Identifier=identifier,
                PatchDocument=json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 120}]),
            )
        )
        assert mutate_code == "ResourceNotFoundException", (
            f"expected an update against the deleted identifier to also fail, got code={mutate_code}"
        )
        expected_mutate = _handler_not_found(_TYPE_NAME, identifier, mutate_message)
        assert mutate_message == expected_mutate, (
            f"expected message {expected_mutate!r}, got {mutate_message!r}"
        )
    else:
        get_resp = cc.get_resource(TypeName=_TYPE_NAME, Identifier=identifier)
        props = json.loads(get_resp["ResourceDescription"]["Properties"])
        assert int(props["VisibilityTimeout"]) == 90, (
            f"expected the winning update to have applied VisibilityTimeout=90, got {props.get('VisibilityTimeout')}"
        )


_TERMINAL = ("SUCCESS", "FAILED", "CANCEL_COMPLETE")


def _wait_for_terminal(cc, token, timeout_s=90.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} never reached terminal state (last={last})")


def _client_error(fn):
    """The (code, message) of the ClientError fn() raises; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected the call to fail, but it succeeded with {result!r}")


def _handler_not_found(type_name, identifier, message):
    """The handler's NotFound text; its RequestToken is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return (
        f"{type_name} Handler returned status FAILED: Resource of type '{type_name}' with "
        f"identifier '{identifier}' was not found. (HandlerErrorCode: NotFound, RequestToken: {token})"
    )


def _cleanup_delete(cc, type_name, identifier):
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        _wait_for_terminal(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=30)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
