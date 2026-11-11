"""endpoint-rejects-unusable-role."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "endpoint-rejects-unusable-role"
GROUP = 'validation'
SERVICES = ['dms']

_DMS_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "dms.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


def _error(fn) -> tuple:
    """The exact (code, message) real AWS returned, or a failure if it returned success."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 — the error is the subject of the assertion
        response = getattr(exc, 'response', None)
        assert isinstance(response, dict), f"expected a modelled AWS error, got {exc!r}"
        return response['Error']['Code'], response['Error'].get('Message')
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _create_endpoint_when_role_lands(dms, **kwargs) -> dict:
    """CreateEndpoint, tolerating IAM's create-to-usable propagation delay on the POSITIVE
    control only. The rejection this check is about names a role that does not exist at all, so
    it is not subject to propagation and is never retried."""
    deadline = time.time() + 180
    while True:
        try:
            return dms.create_endpoint(**kwargs)
        except dms.exceptions.AccessDeniedFault:
            if time.time() >= deadline:
                raise
            time.sleep(2)


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """CreateEndpoint for s3 with a ServiceAccessRoleArn that is not assumable fails at create time with
    AccessDeniedFault and its exact message and creates no endpoint, while the same request with an assumable
    role creates an active endpoint."""
    dms = ctx.client("dms")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-dms-ep-")
    s3.create_bucket(Bucket=bucket,
                     CreateBucketConfiguration={'LocationConstraint': ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    role_name = ctx.unique_name("sim2real-behav-dmsrole-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_DMS_TRUST)
    )['Role']['Arn']
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName='s3-access',
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Action": ["s3:PutObject", "s3:ListBucket"],
                           "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName='s3-access'))

    # The role in this ARN was never created; the name is derived from one we own, so the ARN is
    # well formed and account-correct and the ONLY thing wrong with it is that it does not exist.
    absent_role_arn = f"{role_arn}-absent"
    rejected_id = ctx.unique_name("sim2real-behav-dms-bad-ep-")
    settings = {'BucketName': bucket, 'BucketFolder': 'out'}

    code, message = _error(lambda: dms.create_endpoint(
        EndpointIdentifier=rejected_id, EndpointType='target', EngineName='s3',
        S3Settings=dict(settings, ServiceAccessRoleArn=absent_role_arn),
    ))
    assert code == 'AccessDeniedFault', (
        f"CreateEndpoint with an unusable ServiceAccessRoleArn was rejected as {code!r}, "
        f"expected 'AccessDeniedFault'"
    )
    assert message == f"The IAM Role {absent_role_arn} is not configured properly.AccessDenied", (
        f"CreateEndpoint with an unusable ServiceAccessRoleArn gave message {message!r}"
    )

    # ...and nothing was stored. DMS answers a filter that matches nothing by raising, not by
    # returning an empty list, so absence is asserted through the error code.
    absent_code, absent_message = _error(lambda: dms.describe_endpoints(
        Filters=[{'Name': 'endpoint-id', 'Values': [rejected_id]}]
    ))
    assert absent_code == 'ResourceNotFoundFault', (
        f"looking up the refused endpoint {rejected_id!r} gave {absent_code!r}, expected "
        f"'ResourceNotFoundFault' — a refused create must leave no endpoint behind"
    )
    assert absent_message == "No Endpoints found matching provided filters", (
        f"looking up the refused endpoint {rejected_id!r} gave message {absent_message!r}"
    )

    # Positive control: the same request with an assumable role is accepted.
    accepted_id = ctx.unique_name("sim2real-behav-dms-ok-ep-")
    created = _create_endpoint_when_role_lands(
        dms,
        EndpointIdentifier=accepted_id, EndpointType='target', EngineName='s3',
        S3Settings=dict(settings, ServiceAccessRoleArn=role_arn),
    )['Endpoint']
    ctx.on_cleanup(lambda: dms.delete_endpoint(EndpointArn=created['EndpointArn']))
    assert created['EndpointIdentifier'] == accepted_id, (
        f"created endpoint reports identifier {created['EndpointIdentifier']!r}, expected "
        f"{accepted_id!r}"
    )
    assert created['Status'] == 'active', (
        f"a freshly created endpoint reports Status {created['Status']!r}, expected 'active'"
    )
    assert created['S3Settings']['ServiceAccessRoleArn'] == role_arn, (
        f"created endpoint echoed ServiceAccessRoleArn "
        f"{created['S3Settings']['ServiceAccessRoleArn']!r}, expected {role_arn!r}"
    )

    found = dms.describe_endpoints(
        Filters=[{'Name': 'endpoint-id', 'Values': [accepted_id]}]
    )['Endpoints']
    assert [e['EndpointArn'] for e in found] == [created['EndpointArn']], (
        f"describe of {accepted_id!r} returned {[e['EndpointArn'] for e in found]!r}, expected "
        f"exactly the endpoint just created"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
