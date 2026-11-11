"""list-pagination-stability."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-pagination-stability"
GROUP = 'pagination'
SERVICES = ['cloudformation']


def _client_error(fn):
    """Call fn(); return the botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

def _wait_stack_status(cf, name, targets, timeout_s=180, interval_s=3):
    """Poll DescribeStacks until StackStatus is in targets; return the stack dict."""
    target = {targets} if isinstance(targets, str) else set(targets)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stacks(StackName=name)["Stacks"][0]
        except ClientError:
            last = None
        if last is not None and last.get("StackStatus") in target:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {name} did not reach {target} (last={last.get('StackStatus') if last else None!r})"
    )

def _describe_stack(cf, name):
    resp = cf.describe_stacks(StackName=name)
    stacks = resp.get("Stacks", [])
    return stacks[0] if stacks else None

def _parameterized_topic_template(logical_id="Topic", default="v1"):
    return json.dumps({
        "Parameters": {"TagValue": {"Type": "String", "Default": default}},
        "Resources": {logical_id: {"Type": "AWS::SNS::Topic",
            "Properties": {"Tags": [{"Key": "probe", "Value": {"Ref": "TagValue"}}]}}},
        "Outputs": {"TopicArn": {"Value": {"Ref": logical_id}}},
    })

def _multi_resource_template(count):
    resources = {f"Topic{i}": {"Type": "AWS::SNS::Topic", "Properties": {}} for i in range(count)}
    return json.dumps({"Resources": resources})


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListStacks/ListStackResources pages have no duplicates or omissions, list the check's own
    stacks on both of two immediate listings, and reject a bogus NextToken with ValidationError."""
    cf = ctx.client("cloudformation")
    created = []
    for i in range(3):
        n = ctx.unique_name(f"sim2real-behav-page{i}-")
        cf.create_stack(
            StackName=n,
            TemplateBody=_parameterized_topic_template(),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda name=n: cf.delete_stack(StackName=name))
        created.append(n)
    for n in created:
        _wait_stack_status(cf, n, {"CREATE_COMPLETE"})

    def collect_stack_ids():
        ids: list = []
        token = None
        while True:
            kwargs = {}
            if token:
                kwargs["NextToken"] = token
            resp = cf.list_stacks(**kwargs)
            ids.extend(s["StackId"] for s in resp.get("StackSummaries", []))
            token = resp.get("NextToken")
            if not token:
                break
        return ids

    pass1 = collect_stack_ids()
    assert len(pass1) == len(set(pass1)), "ListStacks returned a duplicate StackId across pages"
    our_ids = {_describe_stack(cf, n)["StackId"] for n in created}
    assert our_ids.issubset(set(pass1)), "not all created stacks appeared in the full listing"

    pass2 = collect_stack_ids()
    assert len(pass2) == len(set(pass2)), "ListStacks returned a duplicate StackId on the second pass"
    # Other callers create and delete stacks in the same account, so only this check's own stacks
    # are graded across the two listings.
    assert our_ids.issubset(set(pass2)), "a created stack dropped out of the second full listing"

    # A multi-resource stack, to exercise ListStackResources pagination.
    multi_name = ctx.unique_name("sim2real-behav-pagemulti-")
    cf.create_stack(
        StackName=multi_name,
        TemplateBody=_multi_resource_template(6),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=multi_name))
    _wait_stack_status(cf, multi_name, {"CREATE_COMPLETE"})

    def collect_resource_ids():
        ids: list = []
        token = None
        while True:
            kwargs = {"StackName": multi_name}
            if token:
                kwargs["NextToken"] = token
            resp = cf.list_stack_resources(**kwargs)
            ids.extend(r["LogicalResourceId"] for r in resp.get("StackResourceSummaries", []))
            token = resp.get("NextToken")
            if not token:
                break
        return ids

    res1 = collect_resource_ids()
    assert len(res1) == 6, f"expected 6 stack resources, got {len(res1)}: {res1}"
    assert len(res1) == len(set(res1)), "ListStackResources returned a duplicate LogicalResourceId"

    res2 = collect_resource_ids()
    assert sorted(res1) == sorted(res2), "ListStackResources membership changed across immediate repeats"

    # A malformed NextToken must be rejected, not treated as "start from page one".
    bogus_token = "sim2real-behav-bogus-token"
    expected_message = f"{bogus_token} is not a valid NextToken"
    error1 = _client_error(lambda: cf.list_stacks(NextToken=bogus_token))
    assert error1.get("Code") == "ValidationError", f"ListStacks must reject a malformed NextToken with ValidationError, got {error1!r}"
    assert error1.get("Message") == expected_message, f"expected message {expected_message!r}, got {error1!r}"

    error2 = _client_error(
        lambda: cf.list_stack_resources(StackName=multi_name, NextToken=bogus_token)
    )
    assert error2.get("Code") == "ValidationError", f"ListStackResources must reject a malformed NextToken with ValidationError, got {error2!r}"
    assert error2.get("Message") == expected_message, f"expected message {expected_message!r}, got {error2!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
