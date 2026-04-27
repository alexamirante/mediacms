from unittest.mock import Mock, patch

from allauth.socialaccount.models import SocialApp
from django.test import TestCase, override_settings

from identity_providers.adapter import (
    add_user_logo,
    flatten_roles_claim,
    handle_oidc_role_mapping,
)
from rbac.models import RBACGroup, RBACMembership
from users.models import User


PNG_1X1 = (
	b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
	b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDAT\x08\xd7c\xf8\xff\xff?\x00\x05\xfe\x02\xfe"
	b"A\x89\x1b\x8f\x00\x00\x00\x00IEND\xaeB`\x82"
)


class OIDCUserPictureTests(TestCase):
	def test_add_user_logo_from_oidc_picture_when_default_logo(self):
		user = User.objects.create_user(
			username="oidc-user",
			email="oidc@example.com",
			password="test-pass",
			name="OIDC User",
		)

		response = Mock()
		response.read.return_value = PNG_1X1
		response.__enter__ = Mock(return_value=response)
		response.__exit__ = Mock(return_value=False)

		with patch("identity_providers.adapter.urlopen", return_value=response):
			add_user_logo(user, {"picture": "https://example.org/avatar.png"})

		user.refresh_from_db()
		self.assertNotEqual(user.logo.name, "userlogos/user.jpg")
		self.assertIn("userlogos/", user.logo.name)

	@override_settings(OIDC_CLAIMS_MAPPING={"picture": "avatar_url"})
	def test_add_user_logo_from_custom_picture_claim(self):
		user = User.objects.create_user(
			username="oidc-custom-picture",
			email="custom-picture@example.com",
			password="test-pass",
			name="OIDC Custom Picture",
		)

		response = Mock()
		response.read.return_value = PNG_1X1
		response.__enter__ = Mock(return_value=response)
		response.__exit__ = Mock(return_value=False)

		with patch("identity_providers.adapter.urlopen", return_value=response):
			add_user_logo(user, {"avatar_url": "https://example.org/avatar.png"})

		user.refresh_from_db()
		self.assertNotEqual(user.logo.name, "userlogos/user.jpg")
		self.assertIn("userlogos/", user.logo.name)

	def test_does_not_overwrite_existing_logo_with_oidc_picture(self):
		user = User.objects.create_user(
			username="oidc-user-existing",
			email="existing@example.com",
			password="test-pass",
			name="Existing Avatar",
		)
		user.logo.name = "userlogos/custom-avatar.jpg"
		user.save(update_fields=["logo"])

		with patch("identity_providers.adapter.urlopen") as mocked_urlopen:
			add_user_logo(user, {"picture": "https://example.org/avatar.png"})

		user.refresh_from_db()
		mocked_urlopen.assert_not_called()
		self.assertEqual(user.logo.name, "userlogos/custom-avatar.jpg")


class OIDCClaimsMappingTests(TestCase):
	@override_settings(OIDC_CLAIMS_MAPPING={"groups": "custom_groups", "role": "custom_role"})
	def test_role_and_groups_can_be_mapped_from_settings(self):
		user = User.objects.create_user(
			username="oidc-claims",
			email="claims@example.com",
			password="test-pass",
			name="OIDC Claims",
		)
		social_app = SocialApp.objects.create(
			provider="openid_connect",
			provider_id="oidc-test",
			name="OIDC Test",
			client_id="client-id",
			secret="secret",
		)
		group = RBACGroup.objects.create(identity_provider=social_app, uid="group-1", name="Group 1")

		extra_data = {
			"custom_groups": ["group-1"],
			"custom_role": "manager",
		}

		result = handle_oidc_role_mapping(user, extra_data, social_app, oidc_configuration=None)

		self.assertTrue(result)
		membership = RBACMembership.objects.filter(user=user, rbac_group=group).first()
		self.assertIsNotNone(membership)
		self.assertEqual(membership.role, "manager")

class FlattenRolesClaimTests(TestCase):
    def test_string_returns_single_item(self):
        self.assertEqual(flatten_roles_claim("chair"), ["chair"])

    def test_flat_list_returned_as_is(self):
        self.assertEqual(flatten_roles_claim(["chair", "member"]), ["chair", "member"])

    def test_nested_pairs_expand_to_bare_and_combined(self):
        roles = [["chair", "tools"], ["secr", "secretariat"]]
        result = flatten_roles_claim(roles)
        self.assertIn("chair", result)
        self.assertIn("chair:tools", result)
        self.assertIn("secr", result)
        self.assertIn("secr:secretariat", result)

    def test_empty_returns_empty(self):
        self.assertEqual(flatten_roles_claim(None), [])
        self.assertEqual(flatten_roles_claim([]), [])

    def test_mixed_nested_and_flat_items(self):
        roles = [["chair", "tools"], "member"]
        result = flatten_roles_claim(roles)
        self.assertIn("chair", result)
        self.assertIn("chair:tools", result)
        self.assertIn("member", result)


class IETFRolesMappingTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="ietf-user",
            email="ietf@example.com",
            password="test-pass",
            name="IETF User",
        )
        self.social_app = SocialApp.objects.create(
            provider="openid_connect",
            provider_id="ietf-dt",
            name="IETF Datatracker",
            client_id="client-id",
            secret="secret",
        )

    def test_bare_role_matches_global_role_mapping(self):
        from identity_providers.models import IdentityProviderGlobalRole
        IdentityProviderGlobalRole.objects.create(
            identity_provider=self.social_app,
            name="secr",
            map_to="manager",
        )
        ietf_roles = [["chair", "tools"], ["secr", "secretariat"]]
        handle_oidc_role_mapping(self.user, {"roles": ietf_roles}, self.social_app)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_manager)

    def test_combined_role_group_matches_global_role_mapping(self):
        from identity_providers.models import IdentityProviderGlobalRole
        IdentityProviderGlobalRole.objects.create(
            identity_provider=self.social_app,
            name="secr:secretariat",
            map_to="admin",
        )
        ietf_roles = [["secr", "secretariat"]]
        handle_oidc_role_mapping(self.user, {"roles": ietf_roles}, self.social_app)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_superuser)

    def test_unmatched_roles_do_not_raise(self):
        ietf_roles = [["delegate", "ietf"], ["reviewer", "artart"]]
        result = handle_oidc_role_mapping(self.user, {"roles": ietf_roles}, self.social_app)
        # No exception and returns True (even with no RBAC groups)
        self.assertTrue(result)

    @override_settings(OIDC_GLOBAL_ROLE_MAPPINGS={"secr:secretariat": "admin"})
    def test_global_role_mapping_from_settings(self):
        ietf_roles = [["secr", "secretariat"]]
        handle_oidc_role_mapping(self.user, {"roles": ietf_roles}, self.social_app)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_superuser)

    @override_settings(OIDC_GROUP_ROLE_MAPPINGS={"chair:tools": "manager"})
    def test_group_role_mapping_from_settings(self):
        group = RBACGroup.objects.create(
            identity_provider=self.social_app, uid="tools", name="Tools"
        )
        ietf_roles = [["chair", "tools"]]
        handle_oidc_role_mapping(
            self.user,
            {"roles": ietf_roles, "groups": ["tools"]},
            self.social_app,
        )
        membership = RBACMembership.objects.filter(user=self.user, rbac_group=group).first()
        self.assertIsNotNone(membership)
        self.assertEqual(membership.role, "manager")

    @override_settings(
        OIDC_GLOBAL_ROLE_MAPPINGS={"secr": "manager"},
        OIDC_CLAIMS_MAPPING={"role": "roles"},
    )
    def test_settings_mapping_uses_oidc_claims_mapping_role_key(self):
        ietf_roles = [["secr", "secretariat"]]
        handle_oidc_role_mapping(self.user, {"roles": ietf_roles}, self.social_app)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_manager)