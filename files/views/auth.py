from allauth.socialaccount.models import SocialApp
from allauth.account.internal.decorators import login_not_required
from django.conf import settings
from django.http import Http404, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse

from identity_providers.models import LoginOption


def _get_oidc_login_options_from_settings():
    providers = getattr(settings, "SOCIALACCOUNT_PROVIDERS", {})
    oidc_provider = providers.get("openid_connect", {}) if isinstance(providers, dict) else {}
    apps = oidc_provider.get("APPS", []) if isinstance(oidc_provider, dict) else []

    options = []
    for app in apps:
        if not isinstance(app, dict):
            continue
        provider_id = app.get("provider_id")
        if not provider_id:
            continue

        title = app.get("name") or f"Login through {provider_id}"
        options.append({
            "url": f"/accounts/oidc/{provider_id}/login/",
            "title": title,
        })
    return options


def saml_metadata(request):
    if not (hasattr(settings, "USE_SAML") and settings.USE_SAML):
        raise Http404

    xml_parts = ['<?xml version="1.0"?>']
    saml_social_apps = SocialApp.objects.filter(provider='saml')
    entity_id = f"{settings.FRONTEND_HOST}/saml/metadata/"
    xml_parts.append(f'<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" Name="{entity_id}">')  # noqa
    xml_parts.append(f'    <md:EntityDescriptor entityID="{entity_id}">')  # noqa
    xml_parts.append('        <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">')  # noqa

    # Add multiple AssertionConsumerService elements with different indices
    for index, app in enumerate(saml_social_apps, start=1):
        xml_parts.append(
            f'            <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '  # noqa
            f'Location="{settings.FRONTEND_HOST}/accounts/saml/{app.client_id}/acs/" index="{index}"/>'  # noqa
        )

    xml_parts.append('        </md:SPSSODescriptor>')  # noqa
    xml_parts.append('    </md:EntityDescriptor>')  # noqa
    xml_parts.append('</md:EntitiesDescriptor>')  # noqa
    metadata_xml = '\n'.join(xml_parts)
    return HttpResponse(metadata_xml, content_type='application/xml')


@login_not_required
def custom_login_view(request):
    if not (hasattr(settings, "USE_IDENTITY_PROVIDERS") and settings.USE_IDENTITY_PROVIDERS):
        return redirect(reverse('login_system'))

    login_options = []
    existing_urls = set()

    for option in LoginOption.objects.filter(active=True):
        if option.url in existing_urls:
            continue
        existing_urls.add(option.url)
        login_options.append({'url': option.url, 'title': option.title})

    for option in _get_oidc_login_options_from_settings():
        if option["url"] in existing_urls:
            continue
        existing_urls.add(option["url"])
        login_options.append(option)

    return render(request, 'account/custom_login_selector.html', {'login_options': login_options})
