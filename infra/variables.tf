variable "environment" {
  type        = string
  description = "Environment name (e.g., prod, staging, dev)"
}

variable "db_username" {
  type        = string
  description = "Username for the RDS instance"
  sensitive   = true
}

variable "db_password" {
  type        = string
  description = "Password for the RDS instance"
  sensitive   = true
}

variable "database_subnet_ids" {
  type        = list(string)
  description = "List of subnet IDs for the DB subnet group"
}
