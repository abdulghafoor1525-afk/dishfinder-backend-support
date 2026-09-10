"""Unit tests for transactional verification-email delivery."""

import os
import unittest
from unittest.mock import Mock, patch

import httpx

from email_service import EmailConfigurationError, EmailDeliveryError, send_verification_email


class SendVerificationEmailTests(unittest.TestCase):
    def setUp(self):
        self.environment = {
            "RESEND_API_KEY": "re_test_key",
            "EMAIL_FROM": "DishFinder <verify@example.com>",
            "FRONTEND_URL": "https://api.example.com",
            "APP_NAME": "DishFinder",
            "EMAIL_VERIFICATION_EXPIRE_MINUTES": "60",
        }

    @patch("email_service.httpx.post")
    def test_sends_verification_email_through_resend(self, post: Mock):
        post.return_value.raise_for_status.return_value = None

        with patch.dict(os.environ, self.environment, clear=True):
            send_verification_email("person@example.net", "user-id.secret-token")

        post.assert_called_once()
        args, kwargs = post.call_args
        self.assertEqual(args[0], "https://api.resend.com/emails")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer re_test_key")
        self.assertTrue(kwargs["headers"]["Idempotency-Key"].startswith("email-verification-"))
        self.assertEqual(kwargs["json"]["from"], "DishFinder <verify@example.com>")
        self.assertEqual(kwargs["json"]["to"], ["person@example.net"])
        self.assertIn(
            "https://api.example.com/api/auth/verify-email?token=user-id.secret-token",
            kwargs["json"]["text"],
        )

    @patch("email_service.httpx.post")
    def test_requires_resend_api_key(self, post: Mock):
        environment = {**self.environment, "RESEND_API_KEY": ""}

        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaises(EmailConfigurationError):
                send_verification_email("person@example.net", "user-id.secret-token")

        post.assert_not_called()

    @patch("email_service.httpx.post")
    def test_hides_resend_http_failures_behind_delivery_error(self, post: Mock):
        request = httpx.Request("POST", "https://api.resend.com/emails")
        response = httpx.Response(403, request=request)
        post.return_value.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Forbidden", request=request, response=response
        )

        with patch.dict(os.environ, self.environment, clear=True):
            with self.assertRaises(EmailDeliveryError):
                send_verification_email("person@example.net", "user-id.secret-token")


if __name__ == "__main__":
    unittest.main()
