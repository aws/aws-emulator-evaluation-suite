"""session-description-and-tags-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "session-description-and-tags-round-trip"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A non-ASCII Description supplied on CreateSession round-trips via GetSession, and its Tags
    round-trip via GetTags on the session ARN (the Session record itself does not embed Tags)."""
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-glue-session-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    session_id = ctx.unique_name("sim2real-sess-")
    description = "Interactive session used for sim2real fidelity testing: 説明 café 🚀"
    tags = {"team": "data-eng", "purpose": "sim2real-check"}

    def _create_session_with_retry():
        last_err = None
        for _ in range(8):
            try:
                return glue.create_session(
                    Id=session_id,
                    Role=role_arn,
                    Command={"Name": "glueetl", "PythonVersion": "3.9"},
                    Description=description,
                    Tags=tags,
                    Timeout=1,
                    IdleTimeout=1,
                    NumberOfWorkers=2,
                    WorkerType="G.1X",
                    GlueVersion="4.0",
                )
            except Exception as exc:  # IAM role propagation lag on freshly created roles
                last_err = exc
                time.sleep(3)
        raise last_err

    _create_session_with_retry()

    def _cleanup_session():
        from botocore.exceptions import ClientError

        # A session still provisioning refuses deletion with IllegalSessionStateException: retry that.
        deadline = time.monotonic() + 240.0
        while True:
            try:
                glue.delete_session(Id=session_id)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "EntityNotFoundException":
                    return
                if code != "IllegalSessionStateException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup_session)

    session = glue.get_session(Id=session_id)["Session"]
    assert session["Id"] == session_id, f"expected Id {session_id!r}, got {session['Id']!r}"
    assert session["Description"] == description, (
        f"Description did not round-trip: expected {description!r}, got {session.get('Description')!r}"
    )

    session_arn = f"arn:aws:glue:{ctx.region}:{account_id}:session/{session_id}"
    fetched_tags = glue.get_tags(ResourceArn=session_arn)["Tags"]
    assert fetched_tags == tags, f"GetTags mismatch: expected {tags!r}, got {fetched_tags!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
