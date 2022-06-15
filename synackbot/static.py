MESSAGE_TEMPLATE = """
A new message was received regarding a '%s' at target '%s' (%s - %s)

Subject: %s

%s
"""

TARGET_TEMPLATE = """
A new target was registered

Category: %s
Organization: %s
Codename: %s
Updated: %t
Update Date: %s
Active: %s
New: %s
Average Payout: $ %s
Last Vuln Submit: %s
Started: %s
Ends: %s
"""

MISSION_TEMPLATE = """
A new mission was claimed

Title: %s
Category: %s
Attack Types: %s
Organization: %s
Codename: %s
Payout: $ %s
Time to be finished: %s
"""

URL_REGISTERED_SUMMARY = "https://platform.synack.com/api/targets/registered_summary"
URL_SCOPE_SUMMARY = "https://platform.synack.com/api/targets/"
URL_ACTIVATE_TARGET = "https://platform.synack.com/api/launchpoint"
URL_ASSESMENTS = "https://platform.synack.com/api/assessments"
URL_VULNERABILITIES = "https://platform.synack.com/api/vulnerabilities"
URL_DRAFTS = "https://platform.synack.com/api/drafts"
URL_UNREGISTERED_SLUGS = "https://platform.synack.com/api/targets?filter%5Bprimary%5D=unregistered&filter%5Bsecondary%5D=all&filter%5Bcategory%5D=all&sorting%5Bfield%5D=dateUpdated&sorting%5Bdirection%5D=desc&pagination%5Bpage%5D="
URL_PROFILE = "https://platform.synack.com/api/profiles/me"
URL_ANALYTICS = "https://platform.synack.com/api/listing_analytics/categories?listing_id="
URL_HYDRA = "https://platform.synack.com/api/hydra_search/search/"
URL_PUBLISHED_MISSIONS = "https://platform.synack.com/api/tasks/v1/tasks?status=PUBLISHED"
URL_NOTIFICATION_TOKEN = "https://platform.synack.com/api/users/notifications_token"
URL_NOTIFICATION_API = "https://notifications.synack.com/api/v2/"
URL_TRANSACTIONS = "https://platform.synack.com/api/transactions"
URL_UNREAD_MESSAGE_COUNT = "https://platform.synack.com/api/messages/unread_count"
URL_UNREAD_NOTIFICATION_COUNT = "https://notifications.synack.com/api/v2/notifications/unread_count?authorization_token="
URL_CLAIMED_AMOUNT = "https://platform.synack.com/api/tasks/v2/researcher/claimed_amount"
URL_ANALYTICS_SUBMISSION = "https://platform.synack.com/api/listing_analytics/submissions?listing_id="
URL_ANALYTICS_CONNECTIONS = "https://platform.synack.com/api/listing_analytics/connections?listing_id="
URL_ANALYTICS_CATEGROIES = "https://platform.synack.com/api/listing_analytics/categories?listing_id="