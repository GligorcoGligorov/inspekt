package analyze

// SignalIDs lists every signal ID the engine can emit. Metrics use it to
// create each per-signal series at 0 on startup, so a signal's first firing
// is a visible increase (increase() needs an earlier sample). A test parses
// this package and fails if a check emits an ID missing from the list.
var SignalIDs = []string{
	// auth
	"dmarc_fail", "spf_fail", "spf_softfail", "dkim_fail", "auth_unverified",
	// sender
	"missing_from", "reply_to_mismatch", "return_path_mismatch", "display_name_spoof",
	// lookalike
	"punycode_domain", "lookalike_sender", "lookalike_link", "brand_display_name",
	// links
	"ip_literal_url", "html_form_in_email", "link_text_mismatch", "url_shortener", "qr_code_link",
	// hosting
	"abused_hosting_link",
	// hidden content
	"hidden_text_salting",
	// informational (0 points)
	"ai_prompt_injection",
	// attachments
	"double_extension", "executable_attachment", "html_attachment", "macro_document", "container_attachment",
	// lure
	"credential_lure",
	// qr
	"qr_not_scanned",
	// grey-zone review
	"llm_bec", "llm_no_bec", "llm_unavailable",
}
