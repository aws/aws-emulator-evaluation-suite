"""delete-application-idempotent-unknown."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "delete-application-idempotent-unknown"
GROUP = 'applications'
SERVICES = ['elasticbeanstalk']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteApplication on a name that never existed is a no-op, not an error, and is itself idempotent."""
    eb = ctx.client("elasticbeanstalk")
    name = ctx.unique_name("sim2real-behav-eb-app-never-created-")

    def _listed():
        return eb.describe_applications(ApplicationNames=[name])["Applications"]

    assert _listed() == [], "the never-created application must not already be listed"

    # Must not raise, and must not create the application as a side effect.
    eb.delete_application(ApplicationName=name)
    assert _listed() == [], "deleting an unknown application must not create it"

    # Idempotent: a repeated delete of the same unknown name is likewise tolerated.
    eb.delete_application(ApplicationName=name)
    assert _listed() == [], "a repeated delete of an unknown application must remain a no-op"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
