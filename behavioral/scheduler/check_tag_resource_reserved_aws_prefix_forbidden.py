"""tag-resource-reserved-aws-prefix-forbidden."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-reserved-aws-prefix-forbidden"
GROUP = 'overly-permissive'
SERVICES = ['scheduler']

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestThrottled")
_RESERVED_PREFIX_MESSAGE = "Caller is an end user and not allowed to modify system tags."


def _track_group(ctx, name):
    sch = ctx.client("scheduler")
    ctx.on_cleanup(lambda: sch.delete_schedule_group(Name=name))


def _error(fn):
    """The botocore Error dict (Code, Message) a call raised. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _call_retry(fn, *, attempts=10, base_delay=1.5):
    last_exc = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _THROTTLE_CODES:
                raise
            last_exc = exc
            time.sleep(base_delay * (i + 1))
    raise last_exc


def _error_retry(fn, *, attempts=10, base_delay=1.5):
    err = {}
    for i in range(attempts):
        err = _error(fn)
        if err.get("Code") not in _THROTTLE_CODES:
            return err
        time.sleep(base_delay * (i + 1))
    return err


def _tag(ctx, arn, tags):
    sch = ctx.client("scheduler")
    _call_retry(lambda: sch.tag_resource(ResourceArn=arn, Tags=tags))


def _tag_map(ctx, arn):
    sch = ctx.client("scheduler")
    resp = _call_retry(lambda: sch.list_tags_for_resource(ResourceArn=arn))
    return {t["Key"]: t["Value"] for t in resp.get("Tags", [])}

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: tags with the reserved 'aws:' key prefix must be rejected.

    Uses a schedule-GROUP ARN (the only ARN shape Scheduler tagging accepts) so the
    rejection is attributable to the reserved prefix rather than the ARN pattern.
    """
    sch = ctx.client("scheduler")
    name = ctx.unique_name("sim2real-behav-" + "sched-grp-")
    resp = sch.create_schedule_group(Name=name)
    _track_group(ctx, name)
    arn = resp["ScheduleGroupArn"]

    # Sanity: a normal tag on this ARN is accepted, so the ARN itself is valid.
    _tag(ctx, arn, [{"Key": "ok", "Value": "1"}])

    err = _error_retry(
        lambda: sch.tag_resource(ResourceArn=arn, Tags=[{"Key": "aws:reserved", "Value": "x"}])
    )
    code, message = err.get("Code"), err.get("Message")
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == _RESERVED_PREFIX_MESSAGE, (
        f"expected message {_RESERVED_PREFIX_MESSAGE!r}, got {message!r}"
    )

    tag_map = _tag_map(ctx, arn)
    assert "aws:reserved" not in tag_map, f"reserved tag was persisted: {tag_map}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
