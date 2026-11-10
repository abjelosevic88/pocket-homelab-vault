package store

// User is an account on this box.
type User struct {
	ID           int64  `json:"id"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"` // admin | member
	CreatedAt    string `json:"created_at"`
}

// APIToken is a personal access token (hash stored, plaintext shown once).
type APIToken struct {
	ID         int64   `json:"id"`
	UserID     int64   `json:"user_id"`
	Name       string  `json:"name"`
	Prefix     string  `json:"prefix"`
	LastUsedAt *string `json:"last_used_at"`
	CreatedAt  string  `json:"created_at"`
}

// Settings are the box-wide values plus one person's preferences and their
// own connections. Connection modes: "core" (an app link through Pocket
// Core), "direct" (URL + token) or "off"; "" = not chosen yet.
type Settings struct {
	Title         string `json:"title"`
	SetupComplete bool   `json:"setup_complete"`

	DateFormat string `json:"date_format"`
	TimeFormat string `json:"time_format"`
	WeekStart  int    `json:"week_start"` // 1 = Monday, 7 = Sunday

	// The web vault in this browser.
	LockMinutes    int  `json:"lock_minutes"`    // lock after this many idle minutes (0 = only when the tab closes)
	ClipboardClear int  `json:"clipboard_clear"` // seconds before a copied password is wiped (0 = never)
	ShowIcons      bool `json:"show_icons"`      // website icons next to logins
	BreachCheck    bool `json:"breach_check"`    // Health may ask Have I Been Pwned (only the first 5 characters of a hash leave the browser)
	ShareHealth    bool `json:"share_health"`    // share the health numbers (never names or passwords) with other Pocket apps
	Generator      Gen  `json:"generator"`       // the last generator settings

	// Notifications about your vault's security.
	NotifyNewDevice bool   `json:"notify_new_device"` // an app signed in from a device it never used before
	NotifyFailed    bool   `json:"notify_failed"`     // several wrong master passwords or codes in a row
	NotifySecurity  bool   `json:"notify_security"`   // master password, two-step login or KDF changed
	NotifyURL       string `json:"notify_url"`
	NotifyFormat    string `json:"notify_format"` // apprise | ntfy | json

	// Pocket Renewals: "remind me before this card expires".
	RenewalsMode      string `json:"renewals_mode"`
	RenewalsURL       string `json:"renewals_url"`
	RenewalsToken     string `json:"renewals_token"`
	RenewalsPublicURL string `json:"renewals_public_url"`
}

// Gen is the password generator's remembered setup.
type Gen struct {
	Kind      string `json:"kind"` // password | passphrase
	Length    int    `json:"length"`
	Upper     bool   `json:"upper"`
	Lower     bool   `json:"lower"`
	Digits    bool   `json:"digits"`
	Symbols   bool   `json:"symbols"`
	Avoid     bool   `json:"avoid"` // no look-alike characters (l, 1, O, 0)
	Words     int    `json:"words"`
	Separator string `json:"separator"`
	Capital   bool   `json:"capital"`
	Number    bool   `json:"number"`
}
