package data

type CredsAWSConnectionResponse struct {
	// connectionid for AWSConnection which was used to generate credentials
	// out: id
	ConnectionID string `json:"connectionid"`

	// LeaseID for generated access
	// out: lease_id
	LeaseID string `json:"lease_id"`

	// LeaseDuration for generated access
	// out: lease_duration
	LeaseDuration int `json:"lease_duration"`

	Data struct {
		// AccessKey for generated access
		// out: access_key
		AccessKey string `json:"access_key"`

		// SecretKey for generated access
		// out: secret_key
		SecretKey string `json:"secret_key"`

		// SessionToken for generated access
		// out: session_token
		SessionToken string `json:"session_token"`
	} `json:"data"`
}
