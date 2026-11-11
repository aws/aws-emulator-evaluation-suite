"""delete-application-removes-from-list."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-application-removes-from-list"
GROUP = 'applications'
SERVICES = ['elasticbeanstalk']

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _err(fn):
    """Call fn(); return (Error.Code, Error.Message), or raise if it unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call against the deleted application to fail, but it succeeded")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteApplication is asynchronous: the application disappears from DescribeApplications,
    and a subsequent mutation naming it fails rather than silently recreating it."""
    eb = ctx.client("elasticbeanstalk")
    name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=name, Tags=[{"Key": "sim2real", "Value": "eb-delete-app"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=name, TerminateEnvByForce=True))

    before = eb.describe_applications(ApplicationNames=[name])["Applications"]
    assert len(before) == 1 and before[0]["ApplicationName"] == name, (
        f"created application must be listed before deletion, got {before!r}"
    )

    eb.delete_application(ApplicationName=name)

    def probe():
        return eb.describe_applications(ApplicationNames=[name])["Applications"]

    _poll_until(probe, lambda apps: apps == [], timeout_s=180, interval_s=10)
    assert probe() == [], "deleted application must eventually stop being listed"

    label = ctx.unique_name("sim2real-behav-v-")
    code, message = _err(lambda: eb.create_application_version(
        ApplicationName=name, VersionLabel=label, AutoCreateApplication=False
    ))
    assert code == "InvalidParameterValue", (
        f"a mutation naming the deleted application must fail with InvalidParameterValue, "
        f"got {code!r}"
    )
    expected = f"No Application named '{name}' found."
    assert message == expected, (
        f"a mutation naming the deleted application must say {expected!r}, got {message!r}"
    )
    assert probe() == [], "the rejected version creation must not resurrect the application"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
