"""e2e-resource-scan-generated-template-to-managed-stack."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "e2e-resource-scan-generated-template-to-managed-stack"
GROUP = "e2e"
SERVICES = ["cloudformation"]


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "plane:control",
    "resource:account-singleton:cfn-generated-template", "resource:account-singleton:cfn-resource-scan",
)
def run(ctx) -> None:
    """Discover an unmanaged resource via a resource scan, generate a template from
    it, execute an IMPORT change set, and confirm the resource is now tracked as a
    managed stack resource end to end."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")

    # 1. Create a resource entirely outside of CloudFormation.
    topic_name = ctx.unique_name("sim2real-behav-unmanaged-")
    topic_arn = sns.create_topic(
        Name=topic_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: _delete_topic_if_exists(ctx, topic_arn))

    # 2. Discover it with a resource scan, scoped to SNS topics to keep it fast.
    scan_id = _start_own_scan(ctx, cfn, ScanFilters=[{"Types": ["AWS::SNS::Topic"]}])
    scan_status = _wait_resource_scan(ctx, scan_id, timeout_s=420)
    assert scan_status == "COMPLETE", f"resource scan ended in {scan_status}, expected COMPLETE"

    found = _find_scanned_topic(ctx, scan_id, topic_arn)
    assert found is not None, "resource scan did not surface the manually-created SNS topic"
    assert found["ManagedByStack"] is False, f"expected the freshly-created topic to be unmanaged, got ManagedByStack={found['ManagedByStack']!r}"

    # 3. Generate a template that describes the discovered resource.
    generated_name = ctx.unique_name("sim2real-behav-gentpl-")
    cfn.create_generated_template(
        GeneratedTemplateName=generated_name,
        Resources=[
            {
                "ResourceType": "AWS::SNS::Topic",
                "ResourceIdentifier": {"TopicArn": topic_arn},
                "LogicalResourceId": "ImportedTopic",
            }
        ],
    )
    ctx.on_cleanup(lambda: cfn.delete_generated_template(GeneratedTemplateName=generated_name))
    gen_status = _wait_generated_template(ctx, generated_name, timeout_s=180)
    assert gen_status == "COMPLETE", f"generated template ended in {gen_status}, expected COMPLETE"

    template_body = cfn.get_generated_template(GeneratedTemplateName=generated_name)["TemplateBody"]

    # 4. Import the discovered resource into a brand-new, CloudFormation-managed stack.
    stack_name = ctx.unique_name("sim2real-behav-importstack-")
    change_set_name = ctx.unique_name("sim2real-behav-importcs-")
    cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        ChangeSetType="IMPORT",
        TemplateBody=template_body,
        ResourcesToImport=[
            {
                "ResourceType": "AWS::SNS::Topic",
                "LogicalResourceId": "ImportedTopic",
                "ResourceIdentifier": {"TopicArn": topic_arn},
            }
        ],
    )
    stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name, stack_id))

    cs_status = _wait_change_set(ctx, stack_name, change_set_name, timeout_s=120)
    assert cs_status == "CREATE_COMPLETE", f"import change set ended in {cs_status}"

    cfn.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)
    stack_status = _wait_stack_terminal(ctx, stack_name, timeout_s=180)
    assert stack_status == "IMPORT_COMPLETE", f"stack import ended in {stack_status}, expected IMPORT_COMPLETE"

    # 5. The previously-unmanaged topic is now a tracked, managed stack resource.
    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    imported = next((r for r in resources if r["LogicalResourceId"] == "ImportedTopic"), None)
    assert imported is not None, (
        f"the stack has no ImportedTopic resource; logical ids: {[r['LogicalResourceId'] for r in resources]!r}"
    )
    assert imported["PhysicalResourceId"] == topic_arn, (
        f"expected the managed stack resource to point at the imported topic {topic_arn!r}, "
        f"got PhysicalResourceId={imported['PhysicalResourceId']!r}"
    )
    # The stack reports IMPORT_COMPLETE; the resource's own latest status is UPDATE_COMPLETE, as
    # the import also applies the template (stack-level tags included) to the imported resource.
    # Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-existing-stack.html
    assert imported["ResourceStatus"] == "UPDATE_COMPLETE", (
        f"expected the imported resource to settle in UPDATE_COMPLETE, got {imported['ResourceStatus']!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _start_own_scan(ctx, cfn, cap_s=600.0, **kwargs):
    """StartResourceScan for this check. The account holds one running scan per region, so while
    another caller's scan holds the slot the call is repeated (capped) until it starts this one.
    A refusal while ListResourceScans shows no scan in progress, twice in a row, fails."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    unexplained = 0
    while True:
        try:
            return cfn.start_resource_scan(**kwargs)["ResourceScanId"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("ResourceScanInProgress", "ResourceScanInProgressException", "ThrottlingException"):
                raise
        if code != "ThrottlingException":
            running = any(
                s.get("Status") == "IN_PROGRESS"
                for page in cfn.get_paginator("list_resource_scans").paginate()
                for s in page.get("ResourceScanSummaries", [])
            )
            unexplained = 0 if running else unexplained + 1
            assert unexplained < 2, (
                f"StartResourceScan answered {code} while ListResourceScans listed no scan IN_PROGRESS"
            )
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("StartResourceScan waiting for the account's running scan to "
                                   "finish: the run budget ended first; not graded")
            raise AssertionError(f"another resource scan held the account's scan slot for {timeout_s}s")
        time.sleep(5)


_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
    "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
}


def _wait_stack_terminal(ctx, stack_name: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    cfn = ctx.client("cloudformation")
    status = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL_STACK_STATUSES:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal status within {timeout_s}s (last={status})")


def _wait_change_set(ctx, stack_name: str, change_set_name: str, timeout_s: float = 120.0, interval_s: float = 5.0) -> str:
    cfn = ctx.client("cloudformation")
    status = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cfn.describe_change_set(StackName=stack_name, ChangeSetName=change_set_name)["Status"]
        if status in ("CREATE_COMPLETE", "FAILED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"change set did not finish within {timeout_s}s (last={status})")


def _wait_resource_scan(ctx, scan_id: str, timeout_s: float = 420.0, interval_s: float = 10.0) -> str:
    cfn = ctx.client("cloudformation")
    status = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cfn.describe_resource_scan(ResourceScanId=scan_id)["Status"]
        if status in ("COMPLETE", "FAILED", "EXPIRED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"resource scan did not finish within {timeout_s}s (last={status})")


def _wait_generated_template(ctx, name: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> str:
    cfn = ctx.client("cloudformation")
    status = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cfn.describe_generated_template(GeneratedTemplateName=name)["Status"]
        if status in ("COMPLETE", "FAILED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"generated template did not finish within {timeout_s}s (last={status})")


def _find_scanned_topic(ctx, scan_id: str, topic_arn: str):
    """The scanned resource for topic_arn across every page of the completed scan, or None."""
    cfn = ctx.client("cloudformation")
    kwargs = {"ResourceScanId": scan_id, "ResourceTypePrefix": "AWS::SNS::Topic"}
    while True:
        page = cfn.list_resource_scan_resources(**kwargs)
        for r in page["Resources"]:
            if r["ResourceIdentifier"].get("TopicArn") == topic_arn:
                return r
        if not page.get("NextToken"):
            return None
        kwargs["NextToken"] = page["NextToken"]


def _delete_stack_and_wait(ctx, stack_name: str, stack_id: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    status = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_id} delete failed: DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id} did not reach DELETE_COMPLETE within {timeout_s}s (last={status})")


def _delete_topic_if_exists(ctx, topic_arn: str) -> None:
    sns = ctx.client("sns")

    try:
        sns.delete_topic(TopicArn=topic_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
