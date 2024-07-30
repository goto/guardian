package gate

type Group struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	GID         int     `json:"gid"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
	DeletedBy   string  `json:"deleted_by"`
	DeletedAt   string  `json:"deleted_at"`
	Description *string `json:"description"`
}
