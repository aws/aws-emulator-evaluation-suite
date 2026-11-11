"""create-application-duplicate-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-application-duplicate-name-rejected"
GROUP = 'applications'
SERVICES = ['elasticbeanstalk']

_TAGS = [{"Key": "sim2real-behav-check", "Value": CHECK}]


def _error_code(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApplication is NOT an upsert: a second call with the same name is rejected, and
    once the conflicting application is gone the identical call succeeds."""
    eb = ctx.client("elasticbeanstalk")
    name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=name, Description="first", Tags=_TAGS)
    ctx.on_cleanup(lambda _n=name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))

    error = _error_code(
        lambda: eb.create_application(ApplicationName=name, Description="second", Tags=_TAGS)
    )
    code = error.get("Code")
    assert code == "InvalidParameterValue", (
        f"re-creating an existing application must fail with InvalidParameterValue, got {code!r}"
    )
    expected = f"Application {name} already exists."
    assert error.get("Message") == expected, f"expected message {expected!r}, got {error.get('Message')!r}"

    described = eb.describe_applications(ApplicationNames=[name])
    apps = described["Applications"]
    assert len(apps) == 1, "duplicate CreateApplication must not create a second application"
    assert apps[0]["Description"] == "first", (
        "the rejected duplicate must not mutate the existing application"
    )

    eb.delete_application(ApplicationName=name, TerminateEnvByForce=True)
    _poll_until(
        lambda: eb.describe_applications(ApplicationNames=[name])["Applications"],
        lambda apps: apps == [],
        timeout_s=180,
        description="DeleteApplication removing it from DescribeApplications",
    )

    restored = eb.create_application(ApplicationName=name, Description="restored", Tags=_TAGS)
    assert restored["Application"]["ApplicationName"] == name, (
        "once the conflicting application is deleted, the identical CreateApplication must succeed"
    )
    restored_apps = eb.describe_applications(ApplicationNames=[name])["Applications"]
    assert len(restored_apps) == 1, "the restore leg must produce exactly one application"
    assert restored_apps[0]["Description"] == "restored", (
        "the restored application must be visible, by name, at an independent read"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
