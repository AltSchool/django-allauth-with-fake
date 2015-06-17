# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import json, re, sys

from allauth.account import app_settings
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import PermissionDenied
from django.urls import reverse, NoReverseMatch, clear_url_caches, set_urlconf

from django.contrib.sites.models import Site
from django.test import TestCase
from django.test.client import RequestFactory
from django.test.utils import override_settings
from django.utils.http import urlquote_plus as urlquote, urlunquote_plus as urlunquote

import importlib
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers.fake.views import FakeOAuth2Adapter

from .views import (
    OAuth2LoginView,
    proxy_login_callback,
    MissingParameter,
)


class OAuth2Tests(TestCase):
    def reload_urls(self):
        clear_url_caches()
        for module in sys.modules:
            if module.endswith("urls"):
                importlib.reload(sys.modules[module])
        clear_url_caches()

    def param(self, param, url):
        # Look for a redirect uri
        url = urlunquote(url)
        m = re.match(".*%s=(.*?)(?:[|&.*]|$)" % param, url)
        if m is None:
            return ""
        return m.group(1)

    def init_request(self, endpoint, params):
        self.request = RequestFactory().get(reverse(endpoint), params)
        SessionMiddleware().process_request(self.request)

    def setUp(self):
        app = SocialApp.objects.create(
            provider=FakeOAuth2Adapter.provider_id,
            name=FakeOAuth2Adapter.provider_id,
            client_id="app123id",
            key=FakeOAuth2Adapter.provider_id,
            secret="dummy",
        )
        app.sites.add(Site.objects.get_current())


@override_settings(
    ACCOUNT_LOGIN_PROXY_REDIRECT_WHITELIST="", ACCOUNT_LOGIN_CALLBACK_PROXY=""
)
class OAuth2TestsNoProxying(OAuth2Tests):
    def setUp(self):
        self.init_request("fake_login", dict(process="login"))
        super(OAuth2TestsNoProxying, self).setUp()

    def test_proxyless_login(self):
        self.reload_urls()
        login_view = OAuth2LoginView.adapter_view(FakeOAuth2Adapter)
        login_response = login_view(self.request)
        self.assertEqual(login_response.status_code, 302)  # Redirect
        self.assertEqual(
            self.param("redirect_uri", login_response["location"]),
            "http://testserver/fake/login/callback/",
        )

    """
    def test_is_not_login_proxy(self):
        self.reload_urls()
        with self.assertRaises(NoReverseMatch):
            reverse("fake_proxy")
    """


@override_settings(
    ACCOUNT_LOGIN_CALLBACK_PROXY="https://loginproxy",
    ACCOUNT_LOGIN_PROXY_REDIRECT_WHITELIST="",
)
class OAuth2TestsUsesProxy(OAuth2Tests):
    def setUp(self):
        self.init_request("fake_login", dict(process="login"))
        super(OAuth2TestsUsesProxy, self).setUp()

    def test_login_by_proxy(self):
        self.reload_urls()
        login_view = OAuth2LoginView.adapter_view(FakeOAuth2Adapter)
        login_response = login_view(self.request)
        self.assertEqual(login_response.status_code, 302)  # Redirect
        self.assertEqual(
            self.param("redirect_uri", login_response["location"]),
            "https://loginproxy/fake/login/callback/proxy/",
        )
        state = self.param("state", login_response["location"])
        state = json.loads(state)
        self.assertEqual(state["host"], "http://testserver/fake/login/")

    def test_is_not_login_proxy(self):
        self.reload_urls()
        with self.assertRaises(NoReverseMatch):
            reverse("fake_proxy")


@override_settings(
    ACCOUNT_LOGIN_PROXY_REDIRECT_WHITELIST="https://cheshirecat,https://tweedledee,",
    ACCOUNT_LOGIN_PROXY_REDIRECT_DOMAIN_WHITELIST="sub.domain.com,",
    ACCOUNT_LOGIN_CALLBACK_PROXY="",
)
class OAuth2TestsIsProxy(OAuth2Tests):
    def tests_is_login_proxy(self):
        self.reload_urls()
        reverse("fake_proxy")

    def test_rejects_request_with_no_host_in_state(self):
        self.reload_urls()
        try:
            reverse("fake_proxy")
        except:
            # for some reason, reverse fails once in this specific test method...
            # but after reloading after failure, it works correctly
            # something going on with URL caching
            self.reload_urls()
        self.init_request("fake_proxy", dict(process="login"))
        with self.assertRaises(MissingParameter):
            proxy_login_callback(self.request, callback_view_name="fake_callback")

    def test_rejects_request_with_unwhitelisted_host(self):
        self.reload_urls()
        state = {"host": "https://bar.domain.com"}
        self.init_request("fake_proxy", dict(process="login", state=json.dumps(state)))
        with self.assertRaises(PermissionDenied):
            proxy_login_callback(self.request, callback_view_name="fake_callback")

    def tests_redirects_request_with_whitelisted_host(self):
        self.reload_urls()
        state = {"host": "https://tweedledee"}
        serialized_state = json.dumps(state)
        self.init_request("fake_proxy", dict(process="login", state=serialized_state))
        proxy_response = proxy_login_callback(
            self.request, callback_view_name="fake_callback"
        )
        self.assertEqual(proxy_response.status_code, 302)  # Redirect
        self.assertEqual(
            proxy_response["location"],
            (
                "https://tweedledee/fake/login/callback/"
                "?process=login&state=%s" % urlquote(serialized_state)
            ),
        )

    def tests_redirects_request_with_domain_whitelisted_host(self):
        self.reload_urls()
        state = {"host": "https://foo.sub.domain.com"}
        serialized_state = json.dumps(state)
        self.init_request("fake_proxy", dict(process="login", state=serialized_state))
        proxy_response = proxy_login_callback(
            self.request, callback_view_name="fake_callback"
        )
        self.assertEqual(proxy_response.status_code, 302)  # Redirect
        self.assertEqual(
            proxy_response["location"],
            (
                "https://foo.sub.domain.com/fake/login/callback/"
                "?process=login&state=%s" % urlquote(serialized_state)
            ),
        )

    def test_rejects_request_with_scheme_mismatch(self):
        self.reload_urls()
        state = {"host": "ftp://tweedledee"}
        self.init_request("fake_proxy", dict(process="login", state=json.dumps(state)))
        with self.assertRaises(PermissionDenied):
            proxy_login_callback(self.request, callback_view_name="fake_callback")

    def test_rejects_request_with_whitelisted_prefix(self):
        self.reload_urls()
        state = {"host": "https://tweedledee.creds4u.biz"}
        self.init_request("fake_proxy", dict(process="login", state=json.dumps(state)))
        with self.assertRaises(PermissionDenied):
            proxy_login_callback(self.request, callback_view_name="fake_callback")
