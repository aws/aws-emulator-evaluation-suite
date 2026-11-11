"""concurrent-resources-limit-exceeded."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "concurrent-resources-limit-exceeded"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

# The wire codes drop the "Exception" suffix of the modeled shape names.
LIMIT_CODE = "ConcurrentResourcesLimitExceeded"
NOT_FOUND_CODE = "GeneratedTemplateNotFound"
_TERMINAL = ("COMPLETE", "FAILED")
_MAX_BURSTS = 5


@tags(
    "axis:rejection", "cap:c1", "concern:negative-classes", "plane:control",
    "resource:account-singleton:cfn-generated-template",
)
def run(ctx) -> None:
    """Concurrent CreateGeneratedTemplate calls beyond the 5 in-flight cap are rejected with
    ConcurrentResourcesLimitExceeded and create nothing; once in-flight templates finish, the
    same call succeeds, so the cap is transient."""
    cfn = ctx.client("cloudformation")

    # Generation finishes within seconds, so bursts of 15 concurrent calls repeat (bounded)
    # until one overlaps enough in-flight generations to cross the cap.
    stack_name = _create_scan_source_stack(ctx, cfn)

    created: list[str] = []
    rejected: list[str] = []
    other_codes: list[str] = []
    all_created: list[str] = []

    def _cleanup() -> None:
        for n in all_created:
            _safe_delete_generated_template(cfn, n)

    ctx.on_cleanup(_cleanup)

    def _create(name: str):
        try:
            cfn.create_generated_template(
                GeneratedTemplateName=name, StackName=stack_name
            )
            return ("ok", name)
        except ClientError as e:
            return (e.response["Error"]["Code"], name)

    for attempt in range(_MAX_BURSTS):
        names = [ctx.unique_name(f"sim2real-gent-{attempt}-{i}-") for i in range(15)]
        with ThreadPoolExecutor(max_workers=len(names)) as pool:
            futures = [pool.submit(_create, n) for n in names]
            for f in as_completed(futures):
                status, name = f.result()
                if status == "ok":
                    created.append(name)
                    all_created.append(name)
                elif status == LIMIT_CODE:
                    rejected.append(name)
                else:
                    other_codes.append(status)
        if rejected or other_codes:
            break
        _wait_all_terminal(cfn, created, deadline_s=_budget_s(ctx, 600.0), ctx=ctx)

    assert created, (
        f"no concurrent CreateGeneratedTemplate call succeeded at all "
        f"(positive control failed): other_codes={other_codes}"
    )

    # message varies: AWS embeds a per-call internal Request ID in the
    # ConcurrentResourcesLimitExceeded message, so only the code is graded.
    assert not other_codes, (
        f"CreateGeneratedTemplate failed with a code other than {LIMIT_CODE!r}: {other_codes}"
    )

    assert rejected, (
        f"{_MAX_BURSTS} bursts of 15 concurrent CreateGeneratedTemplate calls (documented "
        f"cap is 5 in-flight) never triggered {LIMIT_CODE}: created={len(created)}"
    )

    for name in rejected:
        try:
            cfn.describe_generated_template(GeneratedTemplateName=name)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            # message varies: AWS embeds a per-call internal Request ID in the
            # GeneratedTemplateNotFound message, so only the code is graded.
            assert code == NOT_FOUND_CODE, (
                f"rejected name {name!r} was expected to not exist ({NOT_FOUND_CODE}), but "
                f"describe_generated_template failed with {code!r} instead"
            )
        else:
            raise AssertionError(
                f"CreateGeneratedTemplate for {name!r} returned {LIMIT_CODE}, yet "
                "describe_generated_template reports it exists -- the rejection did not "
                "actually prevent creation"
            )

    _wait_all_terminal(cfn, created, deadline_s=_budget_s(ctx, 600.0), ctx=ctx)
    restored_name = ctx.unique_name("sim2real-gent-restored-")
    cfn.create_generated_template(
        GeneratedTemplateName=restored_name, StackName=stack_name
    )
    all_created.append(restored_name)
    restored = _wait_terminal(cfn, restored_name, deadline_s=_budget_s(ctx, 600.0), ctx=ctx)
    assert restored["Status"] == "COMPLETE", (
        f"identical CreateGeneratedTemplate call, fired after the in-flight burst freed a "
        f"slot, did not complete: {restored['Status']!r} ({restored.get('StatusReason')!r})"
    )
    assert restored.get("StatusReason") == "Template complete", restored.get("StatusReason")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_scan_source_stack(ctx, cfn):
    stack_name = ctx.unique_name("sim2real-gentsrc-")
    template = json.dumps(
        {"Resources": {f"Topic{i}": {"Type": "AWS::SNS::Topic"} for i in range(25)}}
    )
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    try:
        waiter.wait(
            StackName=stack_name,
            WaiterConfig={"Delay": 1, "MaxAttempts": max(1, int(_budget_s(ctx, 300.0)))},
        )
    except WaiterError as exc:
        if "Max attempts exceeded" in str(exc) and _budget_spent(ctx):
            raise TimeoutError(f"stack {stack_name} CREATE_COMPLETE: the run budget ended "
                               "first; not graded") from exc
        raise
    return stack_name


def _safe_delete_stack(cfn, stack_name):
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _safe_delete_generated_template(cfn, name):
    # Deleting a template that is still InProgress/Pending also raises
    # ConcurrentResourcesLimitExceeded, so wait for a terminal status first.
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_generated_template(GeneratedTemplateName=name)[
                "Status"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "GeneratedTemplateNotFound":
                raise
            return
        if status in _TERMINAL:
            break
        time.sleep(1)
    try:
        cfn.delete_generated_template(GeneratedTemplateName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "GeneratedTemplateNotFound":
            raise


def _wait_terminal(cfn, name, deadline_s=600.0, ctx=None):
    """Poll DescribeGeneratedTemplate until a terminal status; raise on timeout."""
    deadline = time.monotonic() + deadline_s
    status = None
    while time.monotonic() < deadline:
        desc = cfn.describe_generated_template(GeneratedTemplateName=name)
        status = desc["Status"]
        if status in _TERMINAL:
            return desc
        time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"generated template {name} terminal: the run budget ended first; "
                           "not graded")
    raise AssertionError(
        f"generated template {name} never reached a terminal status within {deadline_s}s; "
        f"last={status!r}"
    )


def _wait_all_terminal(cfn, names, deadline_s=600.0, ctx=None):
    deadline = time.monotonic() + deadline_s
    pending = set(names)
    while pending and time.monotonic() < deadline:
        for name in list(pending):
            try:
                status = cfn.describe_generated_template(GeneratedTemplateName=name)[
                    "Status"
                ]
            except ClientError:
                pending.discard(name)
                continue
            if status in _TERMINAL:
                pending.discard(name)
        if pending:
            time.sleep(1)
    if pending:
        if ctx is not None and _budget_spent(ctx):
            raise TimeoutError(f"generated template(s) {sorted(pending)} terminal: the run "
                               "budget ended first; not graded")
        raise AssertionError(
            f"generated template(s) never reached a terminal status within {deadline_s}s: "
            f"{sorted(pending)}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
