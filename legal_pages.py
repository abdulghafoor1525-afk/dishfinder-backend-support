"""Public, script-free legal pages shared by browser and API routes."""

from html import escape


LEGAL_PAGE_STYLE = """
      :root {
        color-scheme: dark;
        --background: #303743;
        --surface: #3d4451;
        --surface-soft: #454d5b;
        --accent: #d6c5ab;
        --text: #f8fafc;
        --muted: #d8dde5;
        --border: rgba(214, 197, 171, 0.22);
      }

      * { box-sizing: border-box; }

      html { scroll-behavior: smooth; }

      body {
        margin: 0;
        background: var(--background);
        color: var(--text);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        font-size: 17px;
        line-height: 1.7;
        -webkit-font-smoothing: antialiased;
      }

      main {
        width: min(100% - 32px, 820px);
        margin: 0 auto;
        padding: 48px 0;
      }

      article {
        overflow: hidden;
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 22px;
        box-shadow: 0 18px 48px rgba(13, 18, 27, 0.22);
      }

      header {
        padding: 42px 48px 34px;
        background: linear-gradient(145deg, var(--surface-soft), var(--surface));
        border-bottom: 1px solid var(--border);
      }

      .brand {
        margin: 0 0 10px;
        color: var(--accent);
        font-size: 0.82rem;
        font-weight: 700;
        letter-spacing: 0.12em;
        text-transform: uppercase;
      }

      h1 {
        margin: 0;
        color: var(--accent);
        font-size: clamp(2rem, 6vw, 3rem);
        line-height: 1.15;
        letter-spacing: -0.025em;
      }

      .updated {
        margin: 12px 0 0;
        color: var(--muted);
        font-size: 0.95rem;
      }

      .terms { padding: 12px 48px 44px; }

      section {
        padding: 28px 0;
        border-bottom: 1px solid var(--border);
      }

      section:last-child {
        padding-bottom: 0;
        border-bottom: 0;
      }

      h2 {
        margin: 0 0 10px;
        color: var(--accent);
        font-size: 1.25rem;
        line-height: 1.35;
      }

      p { margin: 0; }
      p + p, p + ul { margin-top: 12px; }

      ul {
        margin-bottom: 0;
        padding-left: 1.4rem;
      }

      li { padding-left: 0.25rem; }
      li + li { margin-top: 8px; }

      a {
        color: var(--accent);
        font-weight: 650;
        text-underline-offset: 3px;
      }

      a:hover { text-decoration-thickness: 2px; }

      a:focus-visible {
        outline: 3px solid var(--accent);
        outline-offset: 4px;
        border-radius: 2px;
      }

      @media (max-width: 600px) {
        body { font-size: 16px; }
        main { width: min(100% - 20px, 820px); padding: 18px 0; }
        article { border-radius: 16px; }
        header { padding: 30px 24px 26px; }
        .terms { padding: 8px 24px 32px; }
        section { padding: 24px 0; }
      }

      @media print {
        :root {
          color-scheme: light;
          --background: #ffffff;
          --surface: #ffffff;
          --surface-soft: #ffffff;
          --accent: #222222;
          --text: #222222;
          --muted: #555555;
          --border: #dddddd;
        }

        main { width: 100%; padding: 0; }
        article { border: 0; box-shadow: none; }
      }
    
      nav { display: flex; flex-wrap: wrap; gap: 12px 24px; margin-top: 20px; }
      a { overflow-wrap: anywhere; }
"""


def render_legal_page(title: str, sections: str) -> str:
    """Render trusted, source-controlled policy content in the shared layout."""
    safe_title = escape(title)
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="theme-color" content="#303743">
    <meta name="description" content="{safe_title} for DishFinder and its subscriptions.">
    <title>{safe_title} | DishFinder</title>
    <style>{LEGAL_PAGE_STYLE}</style>
  </head>
  <body>
    <main>
      <article>
        <header>
          <p class="brand">DishFinder</p>
          <h1>{safe_title}</h1>
          <p class="updated">Last updated: <time datetime="2026-09-23">September 23, 2026</time></p>
          <nav aria-label="Legal policies">
            <a href="./terms-of-use">Terms of Use (EULA)</a>
            <a href="./privacy-policy">Privacy Policy</a>
          </nav>
        </header>
        <div class="terms">{sections}</div>
      </article>
    </main>
  </body>
</html>"""


TERMS_OF_USE_HTML = render_legal_page("Terms of Use (EULA)", """
          <section>
            <h2>1. About these terms</h2>
            <p>These terms cover your use of DishFinder, including DishFinder Pro subscriptions. By using DishFinder or purchasing a subscription, you agree to these terms.</p>
            <p>For the iOS app, Apple's <a href="https://www.apple.com/legal/internet-services/itunes/dev/stdeula/">Standard End User License Agreement (EULA)</a> applies unless a custom EULA is provided in the App Store listing. These subscription terms supplement the applicable EULA and do not limit rights you have under applicable consumer law.</p>
          </section>
          <section>
            <h2>2. Using DishFinder</h2>
            <p>DishFinder helps you discover nearby restaurants and save favourites. Use the service lawfully for personal, non-commercial purposes. You are responsible for keeping your account credentials secure. Restaurant information comes from third-party services and may be incomplete or out of date.</p>
          </section>
          <section>
            <h2>3. Subscription plans and benefits</h2>
            <p>DishFinder Pro provides unlimited restaurant searches while your subscription is active. Monthly plans have a one-month billing period; annual plans have a one-year billing period. A registered DishFinder account is required to use paid subscription access.</p>
            <p>The free allowance is three searches, shared across guest sessions and accounts used on the same device. The purchase screen shows the available plan, benefits, billing period, and price in the currency provided by your store before you confirm a purchase.</p>
          </section>
          <section>
            <h2>4. Payment and automatic renewal</h2>
            <p>Payment is charged to your Apple Account or Google Play account when you confirm a purchase, subject to any offer shown at checkout. Subscriptions automatically renew for the same billing period unless you cancel before renewal.</p>
            <p>For Apple subscriptions, turn off renewal at least 24 hours before the current period ends. Your account may be charged for renewal within the 24 hours before that period ends. The renewal price is the price disclosed by the store, subject to any price-change notices and consent required by the store or applicable law.</p>
            <p>If a free trial or introductory offer is available, its duration and subsequent price are shown before purchase. It converts to a paid subscription unless cancelled under the offer's terms; cancel an Apple trial at least 24 hours before it ends to avoid renewal.</p>
          </section>
          <section>
            <h2>5. Managing and cancelling subscriptions</h2>
            <p>On iPhone or iPad, open Settings, tap your name, then Subscriptions, and select DishFinder to manage or cancel your plan. See <a href="https://support.apple.com/en-us/118428">Apple's cancellation instructions</a>. For Google Play purchases, manage your plan in Google Play's Payments &amp; subscriptions settings.</p>
            <p>Cancellation stops future renewals. Paid access normally continues until the end of the current paid period, subject to the store's rules. Uninstalling DishFinder, signing out, or requesting account deletion does not cancel a store subscription.</p>
            <p>Purchases and refunds are managed by the store where you subscribed. For Apple purchases, <a href="https://reportaproblem.apple.com/">request a refund from Apple</a>. Refund eligibility is determined by the store and applicable law; contacting DishFinder support does not itself cancel a subscription or guarantee a refund.</p>
          </section>
          <section>
            <h2>6. Privacy and third-party services</h2>
            <p>Our <a href="./privacy-policy">Privacy Policy</a> explains how DishFinder handles account, location, and subscription information. DishFinder uses services including Google Maps for restaurant results and RevenueCat for subscription management. Store purchases are also subject to the relevant store's terms.</p>
          </section>
          <section>
            <h2>7. Availability and your rights</h2>
            <p>Availability and restaurant information are not guaranteed. Maintenance, network problems, and third-party outages can interrupt service. To the extent permitted by law, the service is provided as available without additional warranties. Nothing in these terms excludes liability or consumer rights that cannot legally be excluded.</p>
          </section>
          <section>
            <h2>8. Changes and contact</h2>
            <p>Updates to these terms will appear on this page with a revised date. Changes remain subject to applicable law and the terms of your store purchase.</p>
            <p>For questions about DishFinder or these terms, contact <a href="mailto:support@dishfinder.online">support@dishfinder.online</a>.</p>
          </section>
""")


PRIVACY_POLICY_HTML = render_legal_page("Privacy Policy", """
          <section>
            <h2>1. About this policy</h2>
            <p>This policy describes how DishFinder handles personal information when you use the app, create an account, search for restaurants, or use a subscription. For privacy questions and requests, contact <a href="mailto:support@dishfinder.online">support@dishfinder.online</a>.</p>
          </section>
          <section>
            <h2>2. Information we collect</h2>
            <ul>
              <li><strong>Account information:</strong> your email address, account identifier, verification status, a hashed password, and a profile picture if you upload one.</li>
              <li><strong>Guest and device information:</strong> installation identifiers, device credentials, session records, and search counts used to maintain guest access, secure sign-in, and apply the free search allowance. On Android, a device identifier is used to derive a hashed identifier for this allowance.</li>
              <li><strong>Search and location information:</strong> the dish you search for, the latitude and longitude sent with your search, search radius, time, and result count. Search coordinates can reveal your precise location. These details are stored in your search history.</li>
              <li><strong>Saved content:</strong> favourite restaurants and their names, addresses, coordinates, and ratings.</li>
              <li><strong>Subscription information:</strong> your account and RevenueCat identifiers, selected plan and product identifiers, access status, price and currency when supplied, expiration and renewal information, store, and pending plan changes. Payment card details are handled by the store and are not collected by the DishFinder backend.</li>
              <li><strong>Support information:</strong> information you choose to send when contacting us.</li>
            </ul>
          </section>
          <section>
            <h2>3. How information is used</h2>
            <p>We use this information to create and secure accounts, send verification emails, find nearby restaurants, save favourites and search history, maintain subscription access, enforce search allowances, prevent misuse, and respond to support requests.</p>
            <p>Location sent with a search is used to find nearby results and calculate distances. You can control the app's location permission in your device settings; restricting access may limit location-based features.</p>
          </section>
          <section>
            <h2>4. Service providers and sharing</h2>
            <ul>
              <li><strong>Apple App Store or Google Play:</strong> handles purchases, billing, renewals, cancellations, and refunds under the store's privacy policy.</li>
              <li><strong>RevenueCat:</strong> processes app user identifiers and purchase and subscription information to manage subscription access.</li>
              <li><strong>Google Maps / Places:</strong> receives the search query, coordinates, and radius needed to return restaurant results.</li>
              <li><strong>Resend:</strong> processes your email address and verification email content to deliver account verification messages.</li>
              <li><strong>Hosting and database providers:</strong> process information needed to operate and store DishFinder's service data.</li>
            </ul>
            <p>We may also disclose information when required by law or where necessary to protect users, address fraud, or enforce our terms. Service providers may process information in countries other than where you live.</p>
            <p>For details about provider practices, see the privacy policies of <a href="https://www.apple.com/legal/privacy/">Apple</a>, <a href="https://policies.google.com/privacy">Google</a>, <a href="https://www.revenuecat.com/privacy/">RevenueCat</a>, and <a href="https://resend.com/legal/privacy-policy">Resend</a>.</p>
          </section>
          <section>
            <h2>5. Retention and security</h2>
            <p>Account data, saved content, search history, device usage records, and subscription records are stored to support the functions described above. Search history is not automatically erased when it falls outside the most recent entries displayed in the app. Signing out, uninstalling the app, or cancelling a subscription does not automatically erase backend records.</p>
            <p>You can contact us to request deletion. Some records may need to be retained for legal obligations, security, fraud prevention, or resolving disputes. Retention depends on the type of record and its purpose; we do not promise a fixed deletion period for all records.</p>
            <p>Passwords are stored as hashes, and account access uses authentication controls. No storage or transmission method can guarantee complete security.</p>
          </section>
          <section>
            <h2>6. Your choices and requests</h2>
            <p>You can manage location permissions through your device, remove favourites or your profile picture using the app's available controls, and manage subscriptions through the store where you purchased them.</p>
            <p>To request access to, correction of, or deletion of your personal information, email <a href="mailto:support@dishfinder.online">support@dishfinder.online</a>. We may need to verify your identity before fulfilling a request. Depending on where you live, you may have additional rights to object to processing, restrict it, or complain to a data protection authority.</p>
            <p>A data deletion request does not cancel your App Store or Google Play subscription. Cancel it separately in the store to stop future billing.</p>
          </section>
          <section>
            <h2>7. Changes to this policy</h2>
            <p>We may update this policy as DishFinder changes. The date at the top identifies the latest revision. For subscription conditions, see our <a href="./terms-of-use">Terms of Use (EULA)</a>.</p>
          </section>
""")
