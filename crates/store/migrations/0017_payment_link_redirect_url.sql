-- Optional post-checkout redirect: developer-supplied via their own API key at link-creation
-- time, used only to send the payer's own browser back to the merchant's site after
-- confirmation. Not attacker-controlled and never fetched server-side, so no SSRF/allowlist
-- validation is needed — same bare-passthrough treatment as image_url.
ALTER TABLE payment_links ADD COLUMN redirect_url TEXT;
