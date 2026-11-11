"""describe-mac-modification-tasks-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-mac-modification-tasks-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeMacModificationTasks: success contract (list payload + DryRun) and MaxResults=0 rejection."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_mac_modification_tasks(MaxResults=1)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    tasks = resp["MacModificationTasks"]
    _assert_page_contract(tasks, resp.get("NextToken"), max_results=1)

    _assert_dry_run_ok(lambda: ec2.describe_mac_modification_tasks(DryRun=True))

    # MaxResults valid range is documented as minimum 1. botocore's parameter validator
    # enforces that client-side (the request never reaches the wire), so a plain
    # ParamValidationError assertion here can never fail against any target — it is
    # never asking the service anything. Disable client-side validation to actually
    # exercise the service-side rejection.
    unvalidated = _unvalidated_client(ctx, "ec2")
    code, message = _client_error(lambda: unvalidated.describe_mac_modification_tasks(MaxResults=0))
    assert code == "InvalidParameter", f"expected InvalidParameter, got {code!r}"
    expected_message = "value 0 for MaxResults is less than required minimum 1"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


def _assert_page_contract(items, next_token, *, max_results):
    # Substantive body/state assertion: the returned page must never exceed the
    # requested MaxResults, and per the documented contract NextToken is null once
    # fewer than MaxResults items come back (there is nothing left to paginate).
    assert isinstance(items, list)
    assert len(items) <= max_results, f"expected at most {max_results} items, got {len(items)}"
    if len(items) < max_results:
        assert not next_token, "NextToken must be empty when the returned page is not full"


def _client_error(fn):
    """Call fn() and return the (code, message) it is refused with; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _unvalidated_client(ctx, service: str):
    """ctx's own client for ``service`` with botocore's client-side parameter validation off."""
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


def _assert_dry_run_ok(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
        assert message == _DRY_RUN_MESSAGE, f"expected {_DRY_RUN_MESSAGE!r}, got {message!r}"
        return
    raise AssertionError("expected DryRunOperation error, call unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
