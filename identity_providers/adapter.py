import base64
import logging

from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.signals import social_account_updated
from django.core.files.base import ContentFile
from django.dispatch import receiver

from identity_providers.models import IdentityProviderUserLog
from rbac.models import RBACGroup, RBACMembership


class IdentityProviderAccountAdapter(DefaultSocialAccountAdapter):
    """Unified social account adapter for SAML and OIDC providers."""

    def is_open_for_signup(self, request, socialaccount):
        return True

    def populate_user(self, request, sociallogin, data):
        user = sociallogin.user

        # Keep current SAML behavior while allowing OIDC users to keep configured usernames.
        if sociallogin.account and sociallogin.account.uid:
            user.username = sociallogin.account.uid

        for item in ["name", "first_name", "last_name", "email"]:
            if data.get(item):
                setattr(user, item, data[item])

        sociallogin.data = data
        return user

    def save_user(self, request, sociallogin, form=None):
        user = super().save_user(request, sociallogin, form)
        perform_user_actions(user, sociallogin.account)
        return user


@receiver(social_account_updated)
def social_account_updated(sender, request, sociallogin, **kwargs):
    common_fields = sociallogin.data
    perform_user_actions(sociallogin.user, sociallogin.account, common_fields)


def perform_user_actions(user, social_account, common_fields=None):
    if common_fields:
        fields_to_update = []
        for item in ["name", "first_name", "last_name", "email"]:
            if common_fields.get(item) and common_fields[item] != getattr(user, item):
                setattr(user, item, common_fields[item])
                fields_to_update.append(item)
        if fields_to_update:
            user.save(update_fields=fields_to_update)

    extra_data = social_account.extra_data or {}
    social_app = get_social_app(social_account)
    saml_configuration = None
    oidc_configuration = None
    if social_app and social_app.provider == "saml":
        saml_configuration = social_app.saml_configurations.first()
    if social_app and social_app.provider == "openid_connect":
        oidc_configuration = social_app.oidc_configurations.first()

    add_user_logo(user, extra_data)

    if saml_configuration:
        handle_saml_role_mapping(user, extra_data, social_app, saml_configuration)
        if saml_configuration.save_saml_response_logs:
            handle_identity_provider_log(user, dict(extra_data), social_app)
    else:
        handle_oidc_role_mapping(user, extra_data, social_app, oidc_configuration)
        if social_app and (not oidc_configuration or oidc_configuration.save_oidc_response_logs):
            handle_identity_provider_log(user, dict(extra_data), social_app)

    return user


def get_social_app(social_account):
    app = getattr(social_account, "app", None)
    if isinstance(app, SocialApp):
        return app

    provider_id = getattr(app, "provider_id", None)
    if provider_id:
        social_app = SocialApp.objects.filter(provider_id=provider_id).first()
        if social_app:
            return social_app

    # SAML in this codebase uses provider_id matching social_account.provider.
    social_app = SocialApp.objects.filter(provider_id=social_account.provider).first()
    if social_app:
        return social_app

    return SocialApp.objects.filter(provider=social_account.provider).first()


def normalize_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        if "," in value:
            return [v.strip() for v in value.split(",") if v.strip()]
        return [value]
    return [value]


def get_claim(extra_data, claim_name, default=None):
    if not claim_name:
        return default
    return extra_data.get(claim_name, default)


def add_user_logo(user, extra_data):
    try:
        if extra_data.get("jpegPhoto") and user.logo.name in ["userlogos/user.jpg", "", None]:
            base64_string = extra_data.get("jpegPhoto")[0]
            image_data = base64.b64decode(base64_string)
            image_content = ContentFile(image_data)
            user.logo.save("user.jpg", image_content, save=True)
    except Exception as e:
        logging.error(e)
    return True


def map_global_and_group_role(user, social_app, role_value):
    role_value = role_value or "member"

    global_role = social_app.global_roles.filter(name=role_value).first()
    if global_role:
        user.set_role_from_mapping(global_role.map_to)

    mapped_role = role_value
    group_role = social_app.group_roles.filter(name=role_value).first()
    if group_role and group_role.map_to in ["member", "contributor", "manager"]:
        mapped_role = group_role.map_to

    if mapped_role not in ["member", "contributor", "manager"]:
        mapped_role = "member"

    return mapped_role


def sync_rbac_memberships(user, social_app, groups, role, remove_from_groups=False):
    if not social_app:
        return False

    rbac_groups = RBACGroup.objects.filter(identity_provider=social_app, uid__in=groups)

    for rbac_group in rbac_groups:
        membership = RBACMembership.objects.filter(user=user, rbac_group=rbac_group).first()
        if membership and role != membership.role:
            membership.role = role
            membership.save(update_fields=["role"])
        if not membership:
            try:
                RBACMembership.objects.create(user=user, rbac_group=rbac_group, role=role)
            except Exception as e:
                logging.error(e)

    if remove_from_groups:
        for group in user.rbac_groups.filter(identity_provider=social_app):
            if group not in rbac_groups:
                group.members.remove(user)

    return True


def handle_saml_role_mapping(user, extra_data, social_app, saml_configuration):
    if not saml_configuration:
        return False

    groups_key = saml_configuration.groups
    groups = normalize_list(extra_data.get(groups_key, [])) if groups_key else []

    role_key = saml_configuration.role
    role_value = extra_data.get(role_key, "student") if role_key else "student"
    role_value = normalize_list(role_value)[0] if role_value else "student"

    role = map_global_and_group_role(user, social_app, role_value)
    return sync_rbac_memberships(user, social_app, groups, role, remove_from_groups=saml_configuration.remove_from_groups)


def handle_oidc_role_mapping(user, extra_data, social_app, oidc_configuration=None):
    if not social_app:
        return False

    groups_claim = getattr(oidc_configuration, "groups", None) or "groups"
    groups = normalize_list(get_claim(extra_data, groups_claim, []))

    role_value = None
    configured_role = getattr(oidc_configuration, "role", None)
    role_keys = [configured_role] if configured_role else []
    role_keys.extend(["role", "roles", "eduPersonPrimaryAffiliation"])
    for key in role_keys:
        candidate = extra_data.get(key)
        if candidate:
            role_value = normalize_list(candidate)[0]
            break

    role = map_global_and_group_role(user, social_app, role_value)
    remove_from_groups = getattr(oidc_configuration, "remove_from_groups", False)
    return sync_rbac_memberships(user, social_app, groups, role, remove_from_groups=remove_from_groups)


def handle_identity_provider_log(user, extra_data, social_app):
    extra_data.pop("jpegPhoto", None)
    IdentityProviderUserLog.objects.create(user=user, identity_provider=social_app, logs=extra_data)
    return True
