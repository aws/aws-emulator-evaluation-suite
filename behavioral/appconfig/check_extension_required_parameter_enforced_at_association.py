"""extension-required-parameter-enforced-at-association."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "extension-required-parameter-enforced-at-association"
GROUP = 'extension'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "extension-required-parameter-enforced-at-association"}

def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _account_from_arn(arn: str) -> str:
    """arn:aws:appconfig:<region>:<account>:extension/<id>/<version> -> <account>."""
    parts = arn.split(":")
    assert len(parts) >= 6 and parts[4], f"unparseable extension Arn: {arn!r}"
    return parts[4]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Required extension parameter is enforced at CreateExtensionAssociation (missing or optional-only
    is refused, supplied round-trips), and Required+Dynamic is refused at CreateExtension.

    Reference: https://docs.aws.amazon.com/appconfig/latest/userguide/working-with-appconfig-extensions-creating-custom.html
    """
    ac = ctx.client("appconfig")
    account = ctx.client("sts").get_caller_identity()["Account"]

    param_name = "notificationtopic"
    other_param = "optionaltag"

    # An extension declaring one required and one optional parameter. AppConfig validates the
    # Uri's shape at create time (a target ARN in the calling account, no {{name}} placeholders)
    # but does not resolve it, so the topic is never created.
    uri = f"arn:aws:sns:{ctx.region}:{account}:{ctx.unique_name('sim2real-behav-uri-topic-')}"
    extension = ac.create_extension(
        Name=ctx.unique_name("sim2real-behav-ext-"),
        Description="required-parameter enforcement probe",
        Actions={
            "ON_DEPLOYMENT_COMPLETE": [
                {
                    "Name": ctx.unique_name("sim2real-behav-action-"),
                    "Uri": uri,
                }
            ]
        },
        Parameters={
            param_name: {"Description": "SNS topic ARN to notify", "Required": True},
            other_param: {"Description": "free-form label", "Required": False},
        },
        Tags=_TAGS,
    )
    ext_id = extension["Id"]
    ctx.on_cleanup(lambda: ac.delete_extension(ExtensionIdentifier=ext_id))

    # The declaration itself must round-trip: an emulator that swallows Parameters fails here
    # before any enforcement is even tested.
    declared = extension.get("Parameters")
    assert declared, (
        "CreateExtension must echo the declared Parameters; an extension whose parameter map "
        "vanishes cannot enforce anything"
    )
    assert set(declared) == {param_name, other_param}, sorted(declared)
    assert declared[param_name]["Required"] is True, declared[param_name]
    assert declared[other_param]["Required"] is False, declared[other_param]
    assert declared[param_name]["Dynamic"] is False, (
        f"a parameter declared without Dynamic must come back Dynamic=False, not absent and not "
        f"true; got {declared[param_name]!r}"
    )
    fetched = ac.get_extension(ExtensionIdentifier=ext_id)
    assert fetched["Parameters"][param_name]["Required"] is True, fetched["Parameters"]
    assert fetched["Actions"]["ON_DEPLOYMENT_COMPLETE"][0]["Uri"] == uri, (
        f"the validated Uri must round-trip unchanged, got "
        f"{fetched['Actions']['ON_DEPLOYMENT_COMPLETE'][0].get('Uri')!r} for {uri!r}"
    )
    assert (
        fetched["Parameters"][param_name]["Description"] == "SNS topic ARN to notify"
    ), fetched["Parameters"][param_name]

    assert _account_from_arn(extension["Arn"]) == account, (
        f"the extension's own Arn must be minted in the calling account {account}, got "
        f"{extension['Arn']!r}"
    )
    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: ac.delete_application(ApplicationId=app_id))
    app_arn = f"arn:aws:appconfig:{ctx.region}:{account}:application/{app_id}"

    # Break exactly one thing: omit the required parameter.
    missing_code, missing_msg = _error(
        lambda: ac.create_extension_association(
            ExtensionIdentifier=ext_id, ResourceIdentifier=app_arn
        )
    )
    assert missing_code == "BadRequestException", (
        f"CreateExtensionAssociation omitting the required parameter {param_name!r} must be "
        f"refused with BadRequestException, got {missing_code!r} — an emulator that accepts it "
        f"defers the failure to a live deployment's action point"
    )
    assert missing_msg == (
        f"Extension {extension['Name']} version {extension['VersionNumber']} has required "
        f"parameters, but no parameters have been supplied"
    ), f"unexpected refusal message: {missing_msg!r}"

    # Supplying ONLY the optional parameter must also be refused: the rule is about the required
    # one specifically, not about Parameters being absent entirely.
    optional_only_code, optional_only_msg = _error(
        lambda: ac.create_extension_association(
            ExtensionIdentifier=ext_id,
            ResourceIdentifier=app_arn,
            Parameters={other_param: "label-value"},
        )
    )
    assert optional_only_code == "BadRequestException", (
        f"supplying only the optional parameter must still be refused for the missing required "
        f"one, got {optional_only_code!r}"
    )
    assert optional_only_msg == (
        f"Parameter {param_name}  is required for extension {ext_id} version "
        f"{extension['VersionNumber']}, but a value has not been supplied."
    ), f"unexpected refusal message: {optional_only_msg!r}"

    # Effect absent: neither refusal created an association.
    listed = ac.list_extension_associations(ResourceIdentifier=app_arn).get("Items", [])
    assert listed == [], (
        f"a refused CreateExtensionAssociation must create nothing; "
        f"ListExtensionAssociations returned {listed!r}"
    )

    # Control: with the required parameter supplied, the association is created and round-trips.
    topic_arn = f"arn:aws:sns:{ctx.region}:{account}:{ctx.unique_name('sim2real-behav-topic-')}"
    association = ac.create_extension_association(
        ExtensionIdentifier=ext_id,
        ResourceIdentifier=app_arn,
        Parameters={param_name: topic_arn},
        Tags=_TAGS,
    )
    assoc_id = association["Id"]
    ctx.on_cleanup(lambda: ac.delete_extension_association(ExtensionAssociationId=assoc_id))
    assert association["Parameters"] == {param_name: topic_arn}, (
        f"the create response must echo the supplied parameters, got "
        f"{association.get('Parameters')!r}"
    )

    got = ac.get_extension_association(ExtensionAssociationId=assoc_id)
    assert got["Parameters"] == {param_name: topic_arn}, (
        f"GetExtensionAssociation must return the stored parameter value, got "
        f"{got.get('Parameters')!r} — an emulator that accepts Parameters and discards them "
        f"produces an association that can never fire correctly"
    )
    assert got["ResourceArn"] == app_arn, got["ResourceArn"]
    assert got["ExtensionArn"] == extension["Arn"], got["ExtensionArn"]
    assert [a["Id"] for a in ac.list_extension_associations(ResourceIdentifier=app_arn)["Items"]] == [
        assoc_id
    ], "the accepted association must be the only one listed for the resource"

    # A parameter cannot be both Required and Dynamic: dynamic parameters are supplied per
    # deployment, so CreateExtension rejects the extension outright.
    conflict_name = ctx.unique_name("sim2real-behav-ext-conflict-")
    conflict_code, conflict_msg = _error(
        lambda: ac.create_extension(
            Name=conflict_name,
            Actions={
                "ON_DEPLOYMENT_COMPLETE": [
                    {
                        "Name": ctx.unique_name("sim2real-behav-action-"),
                        "Uri": uri,
                    }
                ]
            },
            Parameters={param_name: {"Required": True, "Dynamic": True}},
            Tags=_TAGS,
        )
    )
    assert conflict_code == "BadRequestException", (
        f"a parameter marked both Required and Dynamic is contradictory and must be refused at "
        f"CreateExtension with BadRequestException, got {conflict_code!r}"
    )
    assert conflict_msg == (
        f"Extension parameters {param_name} can not be both required and dynamic"
    ), f"unexpected refusal message: {conflict_msg!r}"

    # Effect absent for the second rejection too: the refused extension does not exist.
    extension_names = set()
    token, pages = None, 0
    while pages < 50:
        pages += 1
        page = ac.list_extensions(MaxResults=50, **({"NextToken": token} if token else {}))
        extension_names.update(e["Name"] for e in page.get("Items", []))
        token = page.get("NextToken")
        if not token:
            break
    else:
        raise AssertionError("ListExtensions did not terminate within 50 pages")
    assert conflict_name not in extension_names, (
        f"the refused CreateExtension must create nothing, but {conflict_name!r} appears in "
        f"ListExtensions"
    )
    assert extension["Name"] in extension_names, (
        "the valid extension must still be listed after the refusal"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
