"""list-resource-requests-reflects-create."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}

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
    """Poll GetResourceRequestStatus until the request reaches a terminal
    OperationStatus. Returns the final ProgressEvent dict."""
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
    )
    return holder["event"]

def _delete_quiet(cc, type_name, identifier):
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=60, interval_s=2)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise

def _track(cc, ctx, type_name, identifier):
    ctx.on_cleanup(lambda: _delete_quiet(cc, type_name, identifier))

def _ssm_desired_state(name, value="v1", ptype="String"):
    return json.dumps({"Name": name, "Type": ptype, "Value": value, "Tags": {"sim2real": CHECK}})

CHECK = "list-resource-requests-reflects-create"
GROUP = 'lifecycle'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResourceRequests surfaces a status summary entry matching a recently issued CreateResource request."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-behav-cc-param-")
    resp = cc.create_resource(TypeName=SSM_PARAM_TYPE, DesiredState=_ssm_desired_state(name))
    token = resp["ProgressEvent"]["RequestToken"]
    event = _wait_terminal(cc, token)
    assert event["OperationStatus"] == "SUCCESS", (
        f"prerequisite CreateResource for {name} did not reach SUCCESS: {event}"
    )
    _track(cc, ctx, SSM_PARAM_TYPE, name)

    def probe():
        """Collect request tokens across ALL pages -- ListResourceRequests is
        paginated and returns most-recent-first, so with other requests in
        flight our token can easily fall off the first page."""
        tokens = set()
        next_token = None
        for _ in range(20):  # bounded pagination
            kwargs = {
                "MaxResults": 100,
                "ResourceRequestStatusFilter": {
                    "OperationStatuses": ["SUCCESS"],
                    "Operations": ["CREATE"],
                },
            }
            if next_token:
                kwargs["NextToken"] = next_token
            resp = cc.list_resource_requests(**kwargs)
            tokens.update(
                s["RequestToken"] for s in resp.get("ResourceRequestStatusSummaries", [])
            )
            if token in tokens:
                return tokens
            next_token = resp.get("NextToken")
            if not next_token:
                break
        return tokens

    _poll_until(probe, lambda tokens: token in tokens, timeout_s=90, interval_s=3)

    # the summary for our request must carry the right identity fields
    def find_summary():
        next_token = None
        for _ in range(20):
            kwargs = {"MaxResults": 100}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = cc.list_resource_requests(**kwargs)
            for s in resp.get("ResourceRequestStatusSummaries", []):
                if s["RequestToken"] == token:
                    return s
            next_token = resp.get("NextToken")
            if not next_token:
                break
        return None

    summary = find_summary()
    assert summary is not None, "request summary disappeared from unfiltered listing"
    assert summary["TypeName"] == SSM_PARAM_TYPE, (
        f"expected TypeName {SSM_PARAM_TYPE!r}, got {summary['TypeName']!r}"
    )
    assert summary["Identifier"] == name, (
        f"expected Identifier {name!r}, got {summary['Identifier']!r}"
    )
    assert summary["Operation"] == "CREATE", (
        f"expected Operation 'CREATE', got {summary['Operation']!r}"
    )
    assert summary["OperationStatus"] == "SUCCESS", (
        f"expected OperationStatus 'SUCCESS', got {summary['OperationStatus']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
