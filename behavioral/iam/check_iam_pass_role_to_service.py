"""iam-pass-role-to-service."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "iam-pass-role-to-service"
GROUP = 'pass_role'
SERVICES = ['iam']

MINIMAL_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create a role trusted by Lambda, then create a Lambda referencing it (PassRole path).

    A successful CreateFunction proves iam:PassRole works: Lambda accepts the role
    reference and the function is created with that exact role ARN.
    """
    import io
    import time
    import zipfile

    iam = ctx.client("iam")

    # MINIMAL_TRUST_POLICY already trusts lambda.amazonaws.com.
    role_name = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY,
        Path="/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda n=role_name: iam.delete_role(RoleName=n))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    handler = "def lambda_handler(event, context):\n    return {'ok': True}\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler)
    zip_bytes = buf.getvalue()

    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-behav-fn-")

    # Retry only the transient IAM propagation races (the just-created role's
    # trust reaching Lambda). A genuine PassRole/authorization denial is not in
    # this set, so it surfaces as a real failure.
    deadline = time.monotonic() + 90
    resp = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real:managed": "true"},
            )
            ctx.on_cleanup(lambda n=fn_name: lam.delete_function(FunctionName=n))
            break
        except Exception as exc:  # noqa: BLE001 - inspect for transient markers
            msg = str(exc)
            if "cannot be assumed" in msg or "InvalidParameterValue" in msg:
                last_err = exc
                time.sleep(5)
                continue
            raise
    assert resp is not None, f"Lambda referencing the passed role was never created: {last_err}"
    assert resp["Role"] == role_arn, f"expected function role {role_arn}, got {resp.get('Role')}"
    assert resp["FunctionArn"].endswith(f":function:{fn_name}"), (
        f"unexpected FunctionArn {resp.get('FunctionArn')}"
    )

    # Independent read through a different operation than the mutating CreateFunction:
    # the passed role must have actually been persisted against the function, not just
    # echoed back in the create response.
    cfg = lam.get_function_configuration(FunctionName=fn_name)
    assert cfg["Role"] == role_arn, (
        f"expected function role {role_arn} on independent read, got {cfg.get('Role')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
