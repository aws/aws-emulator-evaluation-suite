"""context-lifecycle-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "context-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Context create->describe->delete transition removes it from lookups."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-context-")
    source_uri = f"https://example.com/sim2real/contexts/{name}"

    create_resp = sm.create_context(
        ContextName=name,
        Source={"SourceUri": source_uri, "SourceType": "Custom"},
        ContextType="Endpoint",
        Description="sim2real behavioral fidelity check",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    context_arn = create_resp["ContextArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_context(ContextName=name)))

    described = sm.describe_context(ContextName=name)
    assert described["ContextArn"] == context_arn, (
        f"expected ContextArn {context_arn!r}, got {described.get('ContextArn')!r}"
    )
    assert described["ContextName"] == name, (
        f"expected ContextName {name!r}, got {described.get('ContextName')!r}"
    )
    assert described["ContextType"] == "Endpoint", (
        f"expected ContextType 'Endpoint', got {described.get('ContextType')!r}"
    )
    assert described["Source"]["SourceUri"] == source_uri, (
        f"expected Source.SourceUri {source_uri!r}, got {described.get('Source', {}).get('SourceUri')!r}"
    )

    sm.delete_context(ContextName=name)

    _poll_until(
        lambda: _context_describable(sm, name),
        lambda describable: not describable,
        timeout_s=60,
        interval_s=3,
    )
    code, message = _error(lambda: sm.describe_context(ContextName=name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code}"
    expected_message = f"Context 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:context/{name}' does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    update_code, update_message = _error(
        lambda: sm.update_context(ContextName=name, Description="post-delete mutation must fail")
    )
    assert update_code == "ResourceNotFound", (
        f"expected UpdateContext on a deleted context to fail with ResourceNotFound, got {update_code}"
    )
    expected_update_message = f"Context 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:context/{name}' does not exist."
    assert update_message == expected_update_message, (
        f"expected message {expected_update_message!r}, got {update_message!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _context_describable(sm, name):
    try:
        sm.describe_context(ContextName=name)
    except ClientError:
        return False
    return True


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
