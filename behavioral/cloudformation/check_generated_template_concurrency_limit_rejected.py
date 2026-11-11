"""generated-template-concurrency-limit-rejected."""
from __future__ import annotations

import concurrent.futures as cf
import json
import random
import time

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "generated-template-concurrency-limit-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_MAX_BURSTS = 3


@tags(
    "axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control",
    "resource:account-singleton:cfn-generated-template",
)
def run(ctx) -> None:
    """Of bursts of 30 concurrent CreateGeneratedTemplate calls (at most 5 may be in flight), some succeed and some
    fail with ConcurrentResourcesLimitExceeded "Rate exceeded. Concurrent template generation limit
    exceeded. ..."; a rejected name is then GeneratedTemplateNotFound on DescribeGeneratedTemplate."""
    cfn = ctx.client("cloudformation")
    stack_name = _create_scan_source_stack(ctx, cfn)

    # These templates resolve almost at once, so the in-flight overlap the quota counts is a
    # race; bursts of 30 repeat (bounded) until one finds more than 5 in flight at one instant,
    # and templates still in flight from an earlier burst count toward the cap of the next.

    def _create(name, deadline=None):
        deadline = time.monotonic() + 60 if deadline is None else deadline
        while True:
            try:
                resp = cfn.create_generated_template(GeneratedTemplateName=name, StackName=stack_name)
                return (name, resp.get("GeneratedTemplateId"), None, None)
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                # Request-rate throttling (Throttling on the wire, ThrottlingException as
                # modeled) is a distinct, transient concern that concurrent firing can trip
                # before the account-wide in-flight quota is even reached; retry it so it never
                # gets misclassified as the quota rejection under test.
                if code in ("Throttling", "ThrottlingException") and time.monotonic() < deadline:
                    time.sleep(random.uniform(1.0, 3.0))
                    continue
                return (name, None, code, exc.response["Error"].get("Message"))

    results = []
    names = []
    for burst in range(_MAX_BURSTS):
        burst_names = [ctx.unique_name(f"sim2real-gt-{burst}-{i}-") for i in range(30)]
        names.extend(burst_names)
        with cf.ThreadPoolExecutor(max_workers=len(burst_names)) as pool:
            burst_results = list(pool.map(_create, burst_names))
        for name, _, err, _ in burst_results:
            if err is None:
                ctx.on_cleanup(lambda n=name: _safe_delete_generated_template(cfn, n))
        results.extend(burst_results)
        if any(err is not None for _, _, err, _ in burst_results):
            break
        left = ctx.time_left()
        if left is not None and left < 30.0:
            break

    succeeded = [name for name, template_id, err, _ in results if err is None]
    rejected = [name for name, _, err, _ in results if err is not None]
    failure_codes = [err for _, _, err, _ in results if err is not None]
    failure_messages = [msg for _, _, err, msg in results if err is not None]

    # Positive control: some calls succeed, so a target that rejects every
    # CreateGeneratedTemplate call with this code does not pass.
    assert succeeded, (
        f"expected at least one of {len(names)} concurrent CreateGeneratedTemplate calls to "
        f"succeed (documented cap is 5 in-flight); all {len(names)} failed with "
        f"codes={failure_codes}, which cannot be distinguished from a target that rejects "
        f"every call regardless of the quota"
    )
    # The cap bounds templates in flight at one instant, not total successes: templates that
    # finish free their slot, so more than 5 of the burst may succeed and no upper bound is asserted.
    # The wire code is "ConcurrentResourcesLimitExceeded", without the modeled "Exception" suffix.
    assert "ConcurrentResourcesLimitExceeded" in failure_codes, (
        f"expected at least one of {len(names)} concurrent CreateGeneratedTemplate calls to hit "
        f"the 5-in-flight quota with ConcurrentResourcesLimitExceeded; got failure "
        f"codes={failure_codes} (succeeded={len(succeeded)})"
    )
    # Every failure must be attributable to the same quota, not some unrelated error.
    # The message ends in a per-call request id: grade its stable prefix and suffix.
    for code, message in zip(failure_codes, failure_messages):
        assert code == "ConcurrentResourcesLimitExceeded", f"unexpected failure code {code!r}"
        assert message.startswith(
            "Rate exceeded. Concurrent template generation limit exceeded. (Service: "
        ) and message.endswith("; Proxy: null)"), f"unexpected failure message {message!r}"

    # Independent read: a rejected CreateGeneratedTemplate leaves no template behind, so
    # DescribeGeneratedTemplate on the same name answers GeneratedTemplateNotFound.
    rejected_name = rejected[0]
    try:
        cfn.describe_generated_template(GeneratedTemplateName=rejected_name)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "GeneratedTemplateNotFound", (
            f"expected DescribeGeneratedTemplate({rejected_name!r}) to 404 with "
            f"GeneratedTemplateNotFound after its create was rejected; got "
            f"{exc.response['Error']['Code']!r}"
        )
        # The message ends in a per-call request id: grade its stable prefix and suffix.
        message = exc.response["Error"].get("Message", "")
        assert message.startswith(
            f"Template with arn {rejected_name} does not exist (Service: "
        ) and message.endswith("; Proxy: null)"), f"GeneratedTemplateNotFound message: {message!r}"
    else:
        raise AssertionError(
            f"DescribeGeneratedTemplate({rejected_name!r}) returned a template even though "
            f"its CreateGeneratedTemplate call was rejected with {failure_codes[0]!r}"
        )


def _create_scan_source_stack(ctx, cfn):
    stack_name = ctx.unique_name("sim2real-gtsrc-")
    template = json.dumps(
        {
            "Resources": {
                **{f"Topic{i}": {"Type": "AWS::SNS::Topic"} for i in range(15)},
                **{f"Queue{i}": {"Type": "AWS::SQS::Queue"} for i in range(15)},
            }
        }
    )
    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    try:
        waiter.wait(
            StackName=stack_name,
            WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(_budget_s(ctx, 300.0) / 2))},
        )
    except WaiterError as exc:
        if "Max attempts exceeded" in str(exc) and _budget_spent(ctx):
            raise TimeoutError(f"stack {stack_name} CREATE_COMPLETE: the run budget ended "
                               "first; not graded") from exc
        raise
    return stack_name


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _safe_delete_stack(cfn, stack_name):
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _safe_delete_generated_template(cfn, name, timeout_s=150.0, interval_s=5.0):
    # Deleting a template that is still InProgress/Pending also throws
    # ConcurrentResourcesLimitExceededException, so wait for a terminal status first;
    # if it never lands, leave it (generated templates auto-expire, no billing impact).
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_generated_template(GeneratedTemplateName=name)["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "GeneratedTemplateNotFound":
                raise
            return
        if status in ("COMPLETE", "FAILED"):
            break
        time.sleep(interval_s)
    try:
        cfn.delete_generated_template(GeneratedTemplateName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "GeneratedTemplateNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
