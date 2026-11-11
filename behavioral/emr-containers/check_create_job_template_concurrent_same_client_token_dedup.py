"""create-job-template-concurrent-same-client-token-dedup."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "create-job-template-concurrent-same-client-token-dedup"
GROUP = "concurrency"
SERVICES = ["emr-containers"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing CreateJobTemplate calls sharing one clientToken and identical params persist one
    template: every success returns the same id, and a call that loses the race fails with
    ValidationException rather than minting a second template."""
    from botocore.exceptions import ClientError

    emrc = ctx.client("emr-containers")
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account}:role/{ctx.unique_name('emrc-exec-')}"
    name = ctx.unique_name("sim2real-jt-")
    token = ctx.unique_name("tok-")
    job_template_data = {
        "executionRoleArn": role_arn,
        "releaseLabel": "emr-6.15.0-latest",
        "jobDriver": {
            "sparkSubmitJobDriver": {"entryPoint": "s3://sim2real-emrc-fixtures/a.py"}
        },
    }

    def _create():
        try:
            return ("ok", emrc.create_job_template(
                name=name, clientToken=token, jobTemplateData=job_template_data,
                tags={"sim2real": CHECK},
            )["id"])
        except ClientError as err:
            error = err.response.get("Error", {})
            return ("err", (error.get("Code"), error.get("Message")))

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: _create(), range(8)))

    successes = [v for k, v in outcomes if k == "ok"]
    failures = [v for k, v in outcomes if k == "err"]

    assert successes, f"expected at least one racer to win, got outcomes={outcomes}"
    assert len(set(successes)) == 1, f"successful racers must share one id, got {set(successes)}"
    assert all(code == "ValidationException" for code, _m in failures), (
        f"losing racers must fail with ValidationException, got {failures}"
    )
    # A loser either hits the client-token check, or loses the service's own storage write race,
    # whose message AWS returns verbatim with a per-request id: only its stable prefix is asserted.
    token_message = "At least one input parameter differs from a previous call using the same client token"
    conflict_prefix = (
        "com.amazonaws.services.dynamodbv2.model.TransactionCanceledException: Transaction cancelled, "
        "please refer cancellation reasons for specific reasons ["
    )
    for _code, message in failures:
        assert message == token_message or message.startswith(conflict_prefix), message

    winning_id = successes[0]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(emrc, winning_id))

    # No fan-out: exactly one template with this name exists.
    matches = [t for t in _list_all(emrc) if t["name"] == name]
    assert len(matches) == 1, (
        f"expected exactly one persisted template named {name!r}, "
        f"got {len(matches)}: {matches}"
    )


def _list_all(emrc):
    out = []
    next_token = None
    for _ in range(50):
        kwargs = {"maxResults": 50}
        if next_token:
            kwargs["nextToken"] = next_token
        page = emrc.list_job_templates(**kwargs)
        out.extend(page.get("templates", []))
        next_token = page.get("nextToken")
        if not next_token:
            break
    return out


def _delete_ignore_not_found(emrc, template_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        emrc.delete_job_template(id=template_id)
    except ClientError as err:
        # A job template already deleted in the run is refused with exactly this error.
        error = err.response["Error"]
        if (error["Code"], error.get("Message")) != (
            "ValidationException", "Template does not exist"
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
