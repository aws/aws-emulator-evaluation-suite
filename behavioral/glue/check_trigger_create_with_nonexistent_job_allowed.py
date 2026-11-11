"""trigger-create-with-nonexistent-job-allowed."""
from __future__ import annotations

from behavioral_harness import tags



CHECK = "trigger-create-with-nonexistent-job-allowed"
GROUP = 'trigger'
SERVICES = ['glue']

def _track_trigger(ctx, glue, name):
    # LIFO: stop_trigger runs before delete_trigger; both best-effort.
    ctx.on_cleanup(lambda: glue.delete_trigger(Name=name))
    ctx.on_cleanup(lambda: glue.stop_trigger(Name=name))

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrigger whose action names a job that does not exist succeeds: GetTrigger returns that
    JobName in its action and State CREATED, as the job is resolved only when the trigger fires.
    """
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-trigger-")
    missing_job = ctx.unique_name("sim2real-behav-no-such-job-")

    glue.create_trigger(
        Name=name,
        Type="ON_DEMAND",
        Actions=[{"JobName": missing_job}],
    )
    _track_trigger(ctx, glue, name)

    trig = glue.get_trigger(Name=name)["Trigger"]
    assert trig["Actions"][0]["JobName"] == missing_job, trig
    assert trig["State"] == "CREATED", trig["State"]

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
