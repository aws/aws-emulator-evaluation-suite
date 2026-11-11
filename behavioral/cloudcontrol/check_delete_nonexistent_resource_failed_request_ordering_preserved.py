"""delete-nonexistent-resource-failed-request-ordering-preserved."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "delete-nonexistent-resource-failed-request-ordering-preserved"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]

_NO_QUEUE = ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist.")
_TYPE_NAME = "AWS::SQS::Queue"
_TERMINAL = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
_PAGE_CAP = 50  # pages of 100 requests


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResource of a never-existing queue resolves FAILED with ErrorCode NotFound, and
    ListResourceRequests keeps that request as a FAILED DELETE whose EventTime precedes the later
    successful CREATE and DELETE of a real queue, which really is gone afterwards."""

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_name = ctx.unique_name("sim2real-cc-missing-")
    bogus_identifier = f"{ctx.client('sqs').meta.endpoint_url}/{account_id}/{bogus_name}"

    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")

    # Precondition: no such queue exists.
    pre_error = _error_code(lambda: sqs.get_queue_attributes(QueueUrl=bogus_identifier, AttributeNames=["QueueArn"]))
    assert pre_error == _NO_QUEUE, f"expected the bogus queue URL to not exist before the test, got {pre_error!r}"

    delete_token = cc.delete_resource(TypeName=_TYPE_NAME, Identifier=bogus_identifier)["ProgressEvent"]["RequestToken"]
    final = _cc_wait_terminal(ctx, delete_token)

    assert final["OperationStatus"] == "FAILED", (
        f"deleting a nonexistent resource must resolve to FAILED, got {final['OperationStatus']}"
    )
    assert final.get("ErrorCode") == "NotFound", (
        f"expected ProgressEvent.ErrorCode='NotFound', got {final.get('ErrorCode')!r}"
    )

    # The forbidden effect never happened: the queue still does not exist.
    post_error = _error_code(lambda: sqs.get_queue_attributes(QueueUrl=bogus_identifier, AttributeNames=["QueueArn"]))
    assert post_error == _NO_QUEUE, (
        f"no queue should exist after a failed delete of a nonexistent resource, got {post_error!r}"
    )

    # The failed request is listed: located by its own RequestToken, never by position.
    failed_entry = _listed_request(cc, delete_token, "DELETE", lambda e: e["OperationStatus"] == "FAILED")
    assert failed_entry["OperationStatus"] == "FAILED", (
        f"expected the listed entry for {delete_token!r} to show OperationStatus=FAILED, got {failed_entry}"
    )
    assert failed_entry["Operation"] == "DELETE", (
        f"expected the listed entry for {delete_token!r} to show Operation=DELETE, got {failed_entry}"
    )
    assert failed_entry["TypeName"] == _TYPE_NAME, (
        f"expected the listed entry for {delete_token!r} to name {_TYPE_NAME}, got {failed_entry}"
    )

    # Positive control: a real create against a real, distinct queue name succeeds, and its
    # request is listed as a successful CREATE initiated after the earlier failed delete.
    real_name = ctx.unique_name("sim2real-cc-real-")
    create_token = _cc_submit_create(
        ctx, _TYPE_NAME, {"QueueName": real_name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
    )
    # Registered before the wait, so a create that never settles is still torn down.
    ctx.on_cleanup(lambda: _cc_delete_created(ctx, create_token))
    create_final = _cc_wait_terminal(ctx, create_token)
    assert create_final["OperationStatus"] == "SUCCESS", f"positive-control create failed: {create_final}"
    identifier = create_final["Identifier"]

    create_entry = _listed_request(cc, create_token, "CREATE", lambda e: e["OperationStatus"] == "SUCCESS")
    assert create_entry["Operation"] == "CREATE" and create_entry["OperationStatus"] == "SUCCESS", (
        f"expected the listed entry for {create_token!r} to show a successful CREATE, got {create_entry}"
    )
    assert failed_entry["EventTime"] < create_entry["EventTime"], (
        f"the failed delete {delete_token!r} was initiated before the create {create_token!r}, but "
        f"ListResourceRequests reports EventTime {failed_entry['EventTime']!r} for it and "
        f"{create_entry['EventTime']!r} for the create"
    )

    # Positive control: deleting a real, existing queue succeeds, so a DeleteResource that fails
    # every request cannot pass as rejecting the nonexistent identifier.
    real_delete_token = cc.delete_resource(TypeName=_TYPE_NAME, Identifier=identifier)["ProgressEvent"]["RequestToken"]
    real_delete_final = _cc_wait_terminal(ctx, real_delete_token)
    assert real_delete_final["OperationStatus"] == "SUCCESS", (
        f"positive control: deleting the real, existing queue {identifier!r} must succeed, "
        f"got {real_delete_final}"
    )
    real_post_error = _error_code(lambda: sqs.get_queue_attributes(QueueUrl=identifier, AttributeNames=["QueueArn"]))
    assert real_post_error == _NO_QUEUE, (
        f"expected {identifier!r} to be gone after its successful delete, got {real_post_error!r}"
    )

    real_delete_entry = _listed_request(
        cc, real_delete_token, "DELETE", lambda e: e["OperationStatus"] == "SUCCESS"
    )
    assert real_delete_entry["Operation"] == "DELETE" and real_delete_entry["OperationStatus"] == "SUCCESS", (
        f"expected the listed entry for {real_delete_token!r} to show a successful DELETE, got {real_delete_entry}"
    )
    assert create_entry["EventTime"] < real_delete_entry["EventTime"], (
        f"the create {create_token!r} was initiated before the real delete {real_delete_token!r}, but "
        f"ListResourceRequests reports EventTime {create_entry['EventTime']!r} for it and "
        f"{real_delete_entry['EventTime']!r} for the delete"
    )
    # The failed request stays listed, FAILED, after later requests succeed.
    still_listed = _listed_request(cc, delete_token, "DELETE", lambda e: True)
    assert still_listed["OperationStatus"] == "FAILED" and still_listed["EventTime"] == failed_entry["EventTime"], (
        f"the failed delete {delete_token!r} must still be listed unchanged after later requests, "
        f"was {failed_entry}, now {still_listed}"
    )


def _listed_request(cc, token: str, operation: str, settled: Callable[[dict], bool]) -> dict:
    """The ListResourceRequests summary carrying `token`, read through every page of the
    `operation` requests: the list is eventually consistent, so this polls (bounded) until the
    entry is present and `settled` holds for it."""

    def probe():
        next_token = None
        for _ in range(_PAGE_CAP):
            kwargs: dict = {"MaxResults": 100, "ResourceRequestStatusFilter": {"Operations": [operation]}}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = cc.list_resource_requests(**kwargs)
            for summary in resp["ResourceRequestStatusSummaries"]:
                if summary["RequestToken"] == token:
                    return summary
            next_token = resp.get("NextToken")
            if not next_token:
                return None
        return None

    return _poll_until(probe, lambda e: e is not None and settled(e), timeout_s=90.0, interval_s=5.0)


def _error_code(fn) -> tuple[str, str]:
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _cc_submit_create(ctx, type_name: str, desired_state: dict) -> str:
    cc = ctx.client("cloudcontrol")
    resp = cc.create_resource(TypeName=type_name, DesiredState=json.dumps(desired_state))
    return resp["ProgressEvent"]["RequestToken"]


def _cc_wait_terminal(ctx, request_token: str, timeout_s: float = 90.0, interval_s: float = 2.0) -> dict:
    cc = ctx.client("cloudcontrol")

    def probe():
        return cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]

    return _poll_until(probe, lambda pe: pe["OperationStatus"] in _TERMINAL, timeout_s=timeout_s, interval_s=interval_s)


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _cc_delete_created(ctx, create_token: str) -> None:
    """Teardown for the queue a create request made, if it made one."""
    final = _cc_wait_terminal(ctx, create_token)
    if final.get("Identifier"):
        _cc_delete_unless_gone(ctx, _TYPE_NAME, final["Identifier"])


def _cc_delete_unless_gone(ctx, type_name: str, identifier: str) -> None:
    """Teardown: delete the resource and wait for the request; only NotFound is not a failure."""
    cc = ctx.client("cloudcontrol")
    token = cc.delete_resource(TypeName=type_name, Identifier=identifier)["ProgressEvent"]["RequestToken"]
    final = _cc_wait_terminal(ctx, token)
    if final["OperationStatus"] != "SUCCESS" and final.get("ErrorCode") != "NotFound":
        raise RuntimeError(f"teardown delete of {identifier!r} did not succeed: {final}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
