import json
from urllib.parse import parse_qs, urlparse

from posthog.test.base import APIBaseTest
from unittest.mock import patch

from django.test import override_settings

import requests
from rest_framework import status

from posthog.api.oauth.toolbar_service import CALLBACK_PATH, get_or_create_toolbar_oauth_application
from posthog.models import Organization, Team, User


@override_settings(TOOLBAR_OAUTH_ENABLED=True)
class TestToolbarOAuthPrimitives(APIBaseTest):
    def setUp(self):
        super().setUp()
        self.team.app_urls = ["https://example.com"]
        self.team.save()

    def _start(self) -> dict:
        response = self.client.post(
            "/api/user/toolbar_oauth_start/",
            data=json.dumps(
                {
                    "app_url": self.team.app_urls[0],
                    "code_challenge": "test_challenge_value",
                    "code_challenge_method": "S256",
                    "user_intent": "edit-action",
                }
            ),
            content_type="application/json",
        )
        assert response.status_code == status.HTTP_200_OK, response.content
        return response.json()

    def test_start_requires_authentication(self):
        self.client.logout()
        response = self.client.post(
            "/api/user/toolbar_oauth_start/",
            data=json.dumps(
                {
                    "app_url": self.team.app_urls[0],
                    "code_challenge": "x",
                    "code_challenge_method": "S256",
                }
            ),
            content_type="application/json",
        )
        assert response.status_code == 401

    def test_exchange_requires_authentication(self):
        self.client.logout()
        response = self.client.post(
            "/api/user/toolbar_oauth_exchange/",
            data=json.dumps({"code": "c", "state": "s", "code_verifier": "v"}),
            content_type="application/json",
        )
        assert response.status_code == 401

    def test_callback_requires_authentication(self):
        self.client.logout()
        response = self.client.get("/toolbar_oauth/callback?code=c&state=s")
        assert response.status_code == 401

    @override_settings(TOOLBAR_OAUTH_ENABLED=False)
    def test_start_disabled(self):
        response = self.client.post(
            "/api/user/toolbar_oauth_start/",
            data=json.dumps({"app_url": self.team.app_urls[0], "code_challenge": "x", "code_challenge_method": "S256"}),
            content_type="application/json",
        )
        assert response.status_code == 404

    def test_start_returns_authorization_url(self):
        data = self._start()
        assert "authorization_url" in data

        parsed = urlparse(data["authorization_url"])
        qs = parse_qs(parsed.query)
        assert parsed.scheme == "https"
        assert parsed.netloc == "testserver"
        assert qs["redirect_uri"][0] == "https://testserver/toolbar_oauth/callback"
        assert "state" in qs
        assert qs["code_challenge_method"][0] == "S256"

    def test_start_rejects_unallowed_url(self):
        response = self.client.post(
            "/api/user/toolbar_oauth_start/",
            data=json.dumps(
                {
                    "app_url": "https://not-allowed.example.com",
                    "code_challenge": "test_challenge_value",
                    "code_challenge_method": "S256",
                }
            ),
            content_type="application/json",
        )
        assert response.status_code == 403

    def test_start_rejects_insecure_non_loopback_app_url(self):
        response = self.client.post(
            "/api/user/toolbar_oauth_start/",
            data=json.dumps(
                {
                    "app_url": "http://example.com",
                    "code_challenge": "test_challenge_value",
                    "code_challenge_method": "S256",
                }
            ),
            content_type="application/json",
        )
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_app_url"

    def test_start_allows_http_loopback_app_url(self):
        self.team.app_urls = [*self.team.app_urls, "http://localhost:3000"]
        self.team.save(update_fields=["app_urls"])

        response = self.client.post(
            "/api/user/toolbar_oauth_start/",
            data=json.dumps(
                {
                    "app_url": "http://localhost:3000",
                    "code_challenge": "test_challenge_value",
                    "code_challenge_method": "S256",
                }
            ),
            content_type="application/json",
        )
        assert response.status_code == 200, response.content

    def test_start_rejects_missing_app_url(self):
        response = self.client.post(
            "/api/user/toolbar_oauth_start/",
            data=json.dumps({"code_challenge": "x", "code_challenge_method": "S256"}),
            content_type="application/json",
        )
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_request"

    def test_start_rejects_missing_code_challenge(self):
        response = self.client.post(
            "/api/user/toolbar_oauth_start/",
            data=json.dumps({"app_url": self.team.app_urls[0], "code_challenge_method": "S256"}),
            content_type="application/json",
        )
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_request"

    def test_start_rejects_invalid_json_body(self):
        response = self.client.post(
            "/api/user/toolbar_oauth_start/",
            data="{not-json",
            content_type="application/json",
        )
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_json"

    def test_start_rejects_invalid_code_challenge_method(self):
        response = self.client.post(
            "/api/user/toolbar_oauth_start/",
            data=json.dumps(
                {
                    "app_url": self.team.app_urls[0],
                    "code_challenge": "test_challenge_value",
                    "code_challenge_method": "plain",
                }
            ),
            content_type="application/json",
        )
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_request"

    def test_oauth_application_is_scoped_per_organization(self):
        base_url = "https://us.posthog.example"

        first_app = get_or_create_toolbar_oauth_application(base_url=base_url, user=self.user)

        other_org = Organization.objects.create(name="Another org")
        other_user = User.objects.create_user(
            email="toolbar-oauth-another-org@example.com",
            first_name="Other",
            password="password",
        )
        other_org.members.add(other_user)
        second_app = get_or_create_toolbar_oauth_application(base_url=base_url, user=other_user)

        assert first_app.id != second_app.id
        assert first_app.organization == self.organization
        assert second_app.organization == other_org

    def test_oauth_application_supports_multiple_redirect_uris_within_org(self):
        first_base_url = "https://us.posthog.example"
        second_base_url = "https://eu.posthog.example"

        first_app = get_or_create_toolbar_oauth_application(base_url=first_base_url, user=self.user)
        second_app = get_or_create_toolbar_oauth_application(base_url=second_base_url, user=self.user)

        assert first_app.id == second_app.id
        second_app.refresh_from_db()

        redirect_uris = {uri for uri in second_app.redirect_uris.split(" ") if uri}
        assert redirect_uris == {
            f"{first_base_url}{CALLBACK_PATH}",
            f"{second_base_url}{CALLBACK_PATH}",
        }

    def test_callback_renders_bridge_with_code_and_state(self):
        response = self.client.get("/toolbar_oauth/callback?code=test_code&state=test_state")

        assert response.status_code == 200
        self.assertContains(response, "openerWindow.postMessage")
        self.assertContains(response, '"code": "test_code"')
        self.assertContains(response, '"state": "test_state"')

    def test_callback_renders_bridge_with_error_payload(self):
        response = self.client.get(
            "/toolbar_oauth/callback?error=access_denied&error_description=user+cancelled&state=test_state"
        )

        assert response.status_code == 200
        self.assertContains(response, '"error": "access_denied"')
        self.assertContains(response, '"error_description": "user cancelled"')
        self.assertContains(response, '"state": "test_state"')

    @override_settings(TOOLBAR_OAUTH_ENABLED=False)
    def test_callback_disabled(self):
        response = self.client.get("/toolbar_oauth/callback?code=test_code&state=test_state")
        assert response.status_code == 404

    @patch("posthog.api.oauth.toolbar_service.requests.post")
    def test_exchange_success(self, mock_post):
        start_data = self._start()
        state = parse_qs(urlparse(start_data["authorization_url"]).query)["state"][0]

        mock_post.return_value.status_code = 200
        mock_post.return_value.content = b'{"access_token":"pha_abc","refresh_token":"phr_abc","token_type":"Bearer","expires_in":3600,"scope":"openid"}'
        mock_post.return_value.json.return_value = {
            "access_token": "pha_abc",
            "refresh_token": "phr_abc",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "openid",
        }

        response = self.client.post(
            "/api/user/toolbar_oauth_exchange/",
            data=json.dumps({"code": "test_code", "state": state, "code_verifier": "test_verifier"}),
            content_type="application/json",
        )
        assert response.status_code == 200, response.content
        assert response.json()["access_token"] == "pha_abc"

    @patch("posthog.api.oauth.toolbar_service.requests.post")
    def test_exchange_handles_network_failure(self, mock_post):
        start_data = self._start()
        state = parse_qs(urlparse(start_data["authorization_url"]).query)["state"][0]
        mock_post.side_effect = requests.RequestException("connection failed")

        response = self.client.post(
            "/api/user/toolbar_oauth_exchange/",
            data=json.dumps({"code": "test_code", "state": state, "code_verifier": "test_verifier"}),
            content_type="application/json",
        )
        assert response.status_code == 500
        assert response.json()["code"] == "token_exchange_unavailable"

    @patch("posthog.api.oauth.toolbar_service.requests.post")
    def test_exchange_rejects_tampered_state(self, mock_post):
        start_data = self._start()
        state = parse_qs(urlparse(start_data["authorization_url"]).query)["state"][0]
        tampered_state = f"{state[:-1]}x"

        response = self.client.post(
            "/api/user/toolbar_oauth_exchange/",
            data=json.dumps({"code": "test_code", "state": tampered_state, "code_verifier": "test_verifier"}),
            content_type="application/json",
        )
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_state"
        mock_post.assert_not_called()

    @patch("posthog.api.oauth.toolbar_service.requests.post")
    def test_exchange_rejects_state_user_mismatch(self, mock_post):
        start_data = self._start()
        state = parse_qs(urlparse(start_data["authorization_url"]).query)["state"][0]

        other_user = User.objects.create_user(
            email="toolbar-oauth-other-user@example.com",
            first_name="Other",
            password="password",
            current_organization=self.organization,
            current_team=self.team,
        )
        self.organization.members.add(other_user)
        self.client.force_login(other_user)

        response = self.client.post(
            "/api/user/toolbar_oauth_exchange/",
            data=json.dumps({"code": "test_code", "state": state, "code_verifier": "test_verifier"}),
            content_type="application/json",
        )
        assert response.status_code == 400
        assert response.json()["code"] == "state_user_mismatch"
        mock_post.assert_not_called()

    @patch("posthog.api.oauth.toolbar_service.requests.post")
    def test_exchange_rejects_state_team_mismatch(self, mock_post):
        start_data = self._start()
        state = parse_qs(urlparse(start_data["authorization_url"]).query)["state"][0]

        other_team = Team.objects.create(organization=self.organization, name="Different Team")
        self.user.current_team = other_team
        self.user.save(update_fields=["current_team"])
        self.client.force_login(self.user)

        response = self.client.post(
            "/api/user/toolbar_oauth_exchange/",
            data=json.dumps({"code": "test_code", "state": state, "code_verifier": "test_verifier"}),
            content_type="application/json",
        )
        assert response.status_code == 400
        assert response.json()["code"] == "state_team_mismatch"
        mock_post.assert_not_called()

    def test_exchange_rejects_invalid_json_body(self):
        response = self.client.post(
            "/api/user/toolbar_oauth_exchange/",
            data="{not-json",
            content_type="application/json",
        )
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_json"

    @patch("posthog.api.oauth.toolbar_service.requests.post")
    def test_exchange_returns_error_for_non_json_token_response(self, mock_post):
        start_data = self._start()
        state = parse_qs(urlparse(start_data["authorization_url"]).query)["state"][0]

        mock_post.return_value.status_code = 502
        mock_post.return_value.content = b"bad gateway html"
        mock_post.return_value.json.side_effect = ValueError("invalid json")

        response = self.client.post(
            "/api/user/toolbar_oauth_exchange/",
            data=json.dumps({"code": "test_code", "state": state, "code_verifier": "test_verifier"}),
            content_type="application/json",
        )
        assert response.status_code == 502
        assert response.json()["code"] == "token_exchange_invalid_response"

    @patch("posthog.api.oauth.toolbar_service.requests.post")
    def test_exchange_replay_fails(self, mock_post):
        start_data = self._start()
        state = parse_qs(urlparse(start_data["authorization_url"]).query)["state"][0]

        mock_post.return_value.status_code = 200
        mock_post.return_value.content = b'{"access_token":"pha_abc","refresh_token":"phr_abc","token_type":"Bearer","expires_in":3600,"scope":"openid"}'
        mock_post.return_value.json.return_value = {
            "access_token": "pha_abc",
            "refresh_token": "phr_abc",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "openid",
        }

        first = self.client.post(
            "/api/user/toolbar_oauth_exchange/",
            data=json.dumps({"code": "test_code", "state": state, "code_verifier": "test_verifier"}),
            content_type="application/json",
        )
        assert first.status_code == 200

        second = self.client.post(
            "/api/user/toolbar_oauth_exchange/",
            data=json.dumps({"code": "test_code", "state": state, "code_verifier": "test_verifier"}),
            content_type="application/json",
        )
        assert second.status_code == 400
        assert second.json()["code"] == "state_replay"
