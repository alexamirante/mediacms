import base64
import logging
import os
from urllib.parse import urlparse
from urllib.request import urlopen

from allauth.socialaccount.providers.openid_connect.views import OpenIDConnectOAuth2Adapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.signals import social_account_updated
from django.conf import settings
from django.core.files.base import ContentFile
from django.dispatch import receiver

from identity_providers.models import IdentityProviderUserLog
from rbac.models import RBACGroup, RBACMembership


def get_oidc_claim_mappings():
    claim_mappings = getattr(settings, "OIDC_CLAIMS_MAPPING", {})
    if isinstance(claim_mappings, dict):
        return claim_mappings
    return {}


def get_mapped_claim_name(claim_name, oidc_configuration=None):
    configured_claim = getattr(oidc_configuration, claim_name, None) if oidc_configuration else None
    if configured_claim:
        return configured_claim
    return get_oidc_claim_mappings().get(claim_name)


def get_first_claim_value(claims, claim_names):
    for claim_name in claim_names:
        if not claim_name:
            continue
        value = claims.get(claim_name)
        if value:
            return value
    return None


def update_user_fields_from_claims(user, claims, oidc_configuration=None, save=False):
    fields_to_update = []

    first_name_value = get_first_claim_value(
        claims,
        [get_mapped_claim_name("first_name", oidc_configuration), "given_name", "first_name"],
    )
    if first_name_value and first_name_value != user.first_name:
        user.first_name = first_name_value
        fields_to_update.append("first_name")

    last_name_value = get_first_claim_value(
        claims,
        [get_mapped_claim_name("last_name", oidc_configuration), "family_name", "last_name"],
    )
    if last_name_value and last_name_value != user.last_name:
        user.last_name = last_name_value
        fields_to_update.append("last_name")

    for field_name in ["name", "email"]:
        field_value = get_first_claim_value(claims, [get_mapped_claim_name(field_name, oidc_configuration), field_name])
        if field_value and field_value != getattr(user, field_name):
            setattr(user, field_name, field_value)
            fields_to_update.append(field_name)

    if save and fields_to_update:
        user.save(update_fields=fields_to_update)

    return fields_to_update


class IdentityProviderAccountAdapter(DefaultSocialAccountAdapter):
    """Unified social account adapter for SAML and OIDC providers."""

    class ConfigurableRedirectOIDCAdapter(OpenIDConnectOAuth2Adapter):
        def get_callback_url(self, request, app):
            override = getattr(settings, "OIDC_REDIRECT_URI", "") or os.getenv(
                "OIDC_REDIRECT_URI", ""
            )
            if override:
                return override
            return super().get_callback_url(request, app)

    def is_open_for_signup(self, request, socialaccount):
        return True

    def get_provider(self, request, provider, client_id=None):
        provider_obj = super().get_provider(request, provider, client_id=client_id)
        if provider_obj.id == "openid_connect":
            override = getattr(settings, "OIDC_REDIRECT_URI", "") or os.getenv(
                "OIDC_REDIRECT_URI", ""
            )
            if override:
                provider_obj.oauth2_adapter_class = self.ConfigurableRedirectOIDCAdapter
        return provider_obj

    def populate_user(self, request, sociallogin, data):
        user = sociallogin.user

        # Keep current SAML behavior while allowing OIDC users to keep configured usernames.
        if sociallogin.account and sociallogin.account.uid:
            user.username = sociallogin.account.uid

        update_user_fields_from_claims(user, data, save=False)

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
    extra_data = social_account.extra_data or {}
    social_app = get_social_app(social_account)
    saml_configuration = None
    oidc_configuration = None
    if social_app and social_app.provider == "saml":
        saml_configuration = social_app.saml_configurations.first()
    if social_app and social_app.provider == "openid_connect":
        oidc_configuration = social_app.oidc_configurations.first()

    if common_fields:
        update_user_fields_from_claims(user, common_fields, oidc_configuration=oidc_configuration, save=True)

    add_user_logo(user, extra_data, oidc_configuration=oidc_configuration)

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


def flatten_roles_claim(roles_value):
    """Normalize an OIDC roles claim to a flat list of candidate strings.

    Handles three formats:
    - Simple string:       "chair"
                           → ["chair"]
    - Flat list:           ["chair", "member"]
                           → ["chair", "member"]
    - Nested [role, group] pairs (IETF-style):
                           [["chair", "tools"], ["member", "llc-staff"]]
                           → ["chair", "chair:tools", "member", "member:llc-staff"]

    For nested pairs both the bare role name and the combined "role:group" key are
    included, so admin can configure mappings at either level of granularity.
    """
    if not roles_value:
        return []
    if isinstance(roles_value, str):
        return [roles_value]
    if isinstance(roles_value, list):
        candidates = []
        for item in roles_value:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                role_name = str(item[0])
                group_name = str(item[1])
                candidates.append(role_name)
                candidates.append(f"{role_name}:{group_name}")
            elif isinstance(item, str):
                candidates.append(item)
        return candidates
    return []


def get_claim(extra_data, claim_name, default=None):
    if not claim_name:
        return default
    return extra_data.get(claim_name, default)


def get_settings_global_role(candidate):
    """Return a global role map_to value from OIDC_GLOBAL_ROLE_MAPPINGS settings, or None."""
    mappings = getattr(settings, "OIDC_GLOBAL_ROLE_MAPPINGS", {})
    return mappings.get(candidate) if isinstance(mappings, dict) else None


def get_settings_group_role(candidate):
    """Return a group role map_to value from OIDC_GROUP_ROLE_MAPPINGS settings, or None."""
    mappings = getattr(settings, "OIDC_GROUP_ROLE_MAPPINGS", {})
    return mappings.get(candidate) if isinstance(mappings, dict) else None


def add_user_logo(user, extra_data, oidc_configuration=None):
    try:
        if user.logo.name not in ["userlogos/user.jpg", "", None]:
            return True

        if extra_data.get("jpegPhoto"):
            base64_string = extra_data.get("jpegPhoto")[0]
            image_data = base64.b64decode(base64_string)
            image_content = ContentFile(image_data)
            user.logo.save("user.jpg", image_content, save=True)
            return True

        picture_claim = get_mapped_claim_name("picture", oidc_configuration) or "picture"
        picture_url = extra_data.get(picture_claim)
        if picture_url and isinstance(picture_url, str):
            parsed = urlparse(picture_url)
            if parsed.scheme in ["http", "https"]:
                file_name = os.path.basename(parsed.path) or "user.jpg"
                if "." not in file_name:
                    file_name = f"{file_name}.jpg"

                with urlopen(picture_url, timeout=5) as response:
                    image_data = response.read()

                if image_data:
                    image_content = ContentFile(image_data)
                    user.logo.save(file_name, image_content, save=True)
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
    groups_claim = get_mapped_claim_name("groups", oidc_configuration) or "groups"
    groups = normalize_list(get_claim(extra_data, groups_claim, []))

    # Extract raw roles value from configured claim or fallback keys.
    roles_raw = None
    configured_role = get_mapped_claim_name("role", oidc_configuration)
    role_keys = [configured_role] if configured_role else []
    role_keys.extend(["role", "roles", "eduPersonPrimaryAffiliation"])
    for key in role_keys:
        candidate = extra_data.get(key)
        if candidate is not None:
            roles_raw = candidate
            break

    # Flatten to candidate strings, supporting nested [role, group] pairs.
    # e.g. [["chair", "tools"], ["secr", "secretariat"]]
    # becomes ["chair", "chair:tools", "secr", "secr:secretariat"]
    role_candidates = flatten_roles_claim(roles_raw)

    # Apply ALL matching global role mappings (e.g. "secr:secretariat" → admin).
    # Priority: DB record first, then OIDC_GLOBAL_ROLE_MAPPINGS from settings.
    for candidate in role_candidates:
        global_role = social_app.global_roles.filter(name=candidate).first() if social_app else None
        if global_role:
            user.set_role_from_mapping(global_role.map_to)
        else:
            settings_global = get_settings_global_role(candidate)
            if settings_global:
                user.set_role_from_mapping(settings_global)

    # Determine RBAC membership role from the first matching group role mapping.
    # Priority: DB record → OIDC_GROUP_ROLE_MAPPINGS from settings → bare valid RBAC role.
    rbac_role = "member"
    valid_rbac_roles = {"member", "contributor", "manager"}
    for candidate in role_candidates:
        group_role = social_app.group_roles.filter(name=candidate).first() if social_app else None
        if group_role and group_role.map_to in valid_rbac_roles:
            rbac_role = group_role.map_to
            break
        settings_group = get_settings_group_role(candidate)
        if settings_group and settings_group in valid_rbac_roles:
            rbac_role = settings_group
            break
        if candidate in valid_rbac_roles:
            rbac_role = candidate
            break

    remove_from_groups = getattr(oidc_configuration, "remove_from_groups", False)
    if not social_app:
        # Without a DB-backed SocialApp we can still apply global role mappings,
        # but RBAC group synchronization cannot run.
        return True

    return sync_rbac_memberships(user, social_app, groups, rbac_role, remove_from_groups=remove_from_groups)


def handle_identity_provider_log(user, extra_data, social_app):
    extra_data.pop("jpegPhoto", None)
    IdentityProviderUserLog.objects.create(user=user, identity_provider=social_app, logs=extra_data)
    return True
