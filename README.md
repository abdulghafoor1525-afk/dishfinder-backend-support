# DishFinder backend

## Public subscription policy pages

These GET endpoints return mobile-friendly `text/html` without requiring a login,
device token, or subscription:

| Page | Browser URL path | API URL path |
| --- | --- | --- |
| Terms of Use (EULA) | `/terms-of-use` | `/api/terms-of-use` |
| Privacy Policy | `/privacy-policy` | `/api/privacy-policy` |

The existing `/terms-of-service` and `/api/terms-of-service` URLs continue to serve
the same updated terms. Content and shared styling live in `legal_pages.py`.
No additional dependencies or environment variables are required.

After deploying this backend, prepend its public HTTPS origin to either pair of
paths. Open both resulting URLs without signing in to verify the deployed pages.

### Connect the mobile purchase screen

Add visible, tappable **Terms of Use (EULA)** and **Privacy Policy** links to the
subscription screen before the purchase action. Use the deployed HTTPS URLs.
The native app is not part of this repository, so this change only supplies the
destinations for those links.

If the iOS app uses SwiftUI's `SubscriptionStoreView`, set each destination with
[`subscriptionStorePolicyDestination(url:for:)`](https://developer.apple.com/documentation/swiftui/view/subscriptionstorepolicydestination(url:for:)),
using `.termsOfService` and `.privacyPolicy`. The view belongs in the iOS app;
it does not run in this Python backend.

Keep the subscription name, benefits, duration, and store-provided localized
price visible on the purchase screen. In App Store Connect, set the Privacy
Policy URL and include the Terms of Use URL in the app description or applicable
EULA metadata, as requested in the rejection notice.

### Content details to confirm before publishing

- The policy reflects the data handled by this backend. Confirm the mobile app's
  additional SDKs, analytics, advertising, crash reporting, and data sharing are
  also covered before using it as the app-wide privacy policy.
- Confirm the existing `support@dishfinder.online` contact is monitored for
  privacy and deletion requests, and that the retention description matches
  operational practice. This change does not implement account deletion.
- The terms link to Apple's Standard EULA unless the App Store listing supplies
  a custom EULA. Confirm that matches the app's App Store Connect configuration.
- Update the policy text and revision date when data practices or terms change.

Reference: [Apple's subscription review guidelines](https://developer.apple.com/app-store/review/guidelines/#subscriptions).
