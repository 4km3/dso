provider "aws" {
  region = "us-west-2"
}

# Insecure S3 bucket configuration - will trigger multiple Checkov alerts
resource "aws_s3_bucket" "data" {
  bucket = "my-insecure-bucket"
}

# Missing encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  
  # Missing rule block intentionally to trigger alert
    # Missing rule block intentionally to trigger alert

}

# Public access - insecure
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Insecure bucket policy allowing all access
resource "aws_s3_bucket_policy" "allow_public_access" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          "${aws_s3_bucket.data.arn}",
          "${aws_s3_bucket.data.arn}/*"
        ]
      }
    ]
  })
}

# EC2 instance with security issues
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  root_block_device {
    encrypted = false  # Missing encryption
  }

  vpc_security_group_ids = [aws_security_group.allow_all.id]

  tags = {
    Name = "InsecureWebServer"
  }
}

# Overly permissive security group
resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    description = "Allow all inbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_all"
  }
}

# RDS instance with security issues
resource "aws_db_instance" "default" {
  identifier           = "insecure-db"
  allocated_storage    = 20
  storage_type         = "gp2"
  engine              = "mysql"
  engine_version      = "5.7"
  instance_class      = "db.t2.micro"
  username            = "admin"
  password            = "insecure_password"  # Hardcoded password
  publicly_accessible = true                 # Publicly accessible
  skip_final_snapshot = true                 # Skips final snapshot
  storage_encrypted   = false                # Unencrypted storage
}

# IAM role with overly permissive policy
resource "aws_iam_role" "admin_role" {
  name = "overly_permissive_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "admin_policy" {
  name = "overly_permissive_policy"
  role = aws_iam_role.admin_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"
        Resource = "*"
      }
    ]
  })
}