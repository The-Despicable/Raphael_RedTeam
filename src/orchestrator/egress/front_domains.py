# CDN fronting domain/IP configuration.
#
# WARNING: The placeholder values below MUST be replaced with your own
# CDN fronting domains before use. The real domains listed here previously
# belonged to Amazon, Cloudflare, Fastly, and Microsoft Azure CDNs.
# Using real third-party domains for CDN fronting is:
#   - Illegal in many jurisdictions
#   - Trivially detectable by the CDN provider
#   - Will result in your traffic being blocked/fingerprinted
#
# Before running in production:
#   1. Set up your own CDN fronting domain (e.g., via Cloudflare Workers,
#      AWS CloudFront with your own distribution, or a reverse proxy)
#   2. Replace the placeholder below with your fronting domain
#   3. Optionally add your CDN's IP ranges to CDN_PROVIDERS

CDN_PROVIDERS = {
    "custom": {
        "domains": ["your-cdn-fronting-domain.example.com"],
        "ranges": [],
    },
}


def get_working_front_domains() -> list:
    return [
        "your-cdn-fronting-domain-1.example.com",
        "your-cdn-fronting-domain-2.example.com",
    ]


def get_cdn_ip_range(name: str) -> list:
    provider = CDN_PROVIDERS.get(name)
    if not provider:
        return []
    return provider.get("ranges", [])
