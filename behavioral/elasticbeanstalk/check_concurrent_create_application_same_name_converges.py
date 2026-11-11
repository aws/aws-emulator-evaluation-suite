"""concurrent-create-application-same-name-converges."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "concurrent-create-application-same-name-converges"
GROUP = 'environment-data-plane'
SERVICES = ['elasticbeanstalk']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing CreateApplication calls on one name yield a single application; losers get a conflict."""
    eb = ctx.client("elasticbeanstalk")
    import concurrent.futures

    raw = eb  # genuine race: every racer calls CreateApplication concurrently

    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else max(1.0, min(60.0, left - 5.0)))
    while True:
        name = ctx.unique_name("sim2real-behav-eb-app-race-")
        tags_arg = [{"Key": "sim2real", "Value": "true"}]
        ctx.on_cleanup(lambda _n=name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))

        def attempt(idx: int, _name=name):
            try:
                raw.create_application(
                    ApplicationName=_name, Description=f"racer-{idx}", Tags=tags_arg
                )
                return ("ok", None, None)
            except Exception as exc:  # noqa: BLE001
                error = getattr(exc, "response", {}).get("Error", {})
                return ("err", error.get("Code"), error.get("Message"))

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            outcomes = list(pool.map(attempt, range(3)))

        successes = [o for o in outcomes if o[0] == "ok"]
        conflicts = [(c, m) for _, c, m in outcomes if _ == "err" and c not in ("Throttling",)]
        if not successes:
            # The whole race was throttled; re-run it on a fresh name until the deadline.
            if time.monotonic() >= deadline:
                break
            time.sleep(2)
            continue

        assert len(successes) == 1, (
            f"exactly one racer must win a CreateApplication race on the same name, "
            f"got {len(successes)} successes: {outcomes!r}"
        )
        assert all(c == "InvalidParameterValue" for c, _m in conflicts), (
            f"losing racers must fail with InvalidParameterValue, got {outcomes!r}"
        )
        expected_message = f"Application {name} already exists."
        for _code, message in conflicts:
            assert message == expected_message, f"losing racer message: {message!r}"
        described = eb.describe_applications(ApplicationNames=[name])
        apps = described["Applications"]
        assert len(apps) == 1, "concurrent creates must converge to exactly one application record"
        assert apps[0]["Description"].startswith("racer-"), (
            f"the surviving application's description must be the winning racer's own, got {apps[0]['Description']!r}"
        )
        return

    raise AssertionError("every attempt at a concurrent CreateApplication race was throttled")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
