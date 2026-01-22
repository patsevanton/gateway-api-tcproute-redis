variable "folder_id" {
  description = "ID of the folder where the resources will be created"
  type        = string
  default     = null
}

variable "address_destroy_wait" {
  description = "How long to wait before deleting the reserved public IP address (helps to avoid 'Address in use' during terraform destroy)"
  type        = string
  default     = "300s"
}