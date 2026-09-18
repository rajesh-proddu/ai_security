package detect

// Detector names — the v1 set of DESIGN §3.3. Policy rules reference these.
const (
	DetectorPII                = "pii"
	DetectorSecrets            = "secrets"
	DetectorCustomDict         = "custom_dict"
	DetectorInjectionHeuristic = "injection_heuristic"
	DetectorInjectionML        = "injection_ml"
	DetectorExfilURL           = "exfil_url"
)

// Finding types are one flat namespace across detectors: DESIGN §3.6's
// `type_in: [card, aws_key, aadhaar]` mixes a secrets type with pii types.

// India pack (DESIGN decision 4) — the only regulated-data pack in v1, framed
// against DPDP Act 2023 categories. US/EU packs are explicitly not in v1.
const (
	TypeAadhaar        = "aadhaar"
	TypePAN            = "pan"
	TypeUPIVPA         = "upi_vpa"
	TypeIFSC           = "ifsc"
	TypeBankAccount    = "bank_account"
	TypeIndianMobile   = "indian_mobile"
	TypeIndianPassport = "indian_passport"
	TypeGSTIN          = "gstin"
	TypeCard           = "card"
	TypeEmail          = "email"
)

// Secrets types. DESIGN §3.3 names the providers (AWS, GitHub, Slack, OpenAI)
// and §3.6 uses `aws_key`; the rest follow the same naming.
const (
	TypeAWSKey      = "aws_key"
	TypeGitHubToken = "github_token"
	TypeSlackToken  = "slack_token"
	TypeOpenAIKey   = "openai_key"
)
