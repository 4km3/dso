provider "aws" {
  region = "us-west-2"
}

# Secure S3 bucket configuration
resource "aws_s3_bucket" "data" {
  bucket = "my-secure-bucket"
}

# Enable encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block public access
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Secure bucket policy with least privilege
resource "aws_s3_bucket_policy" "restricted_access" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RestrictedReadGetObject"
        Effect    = "Allow"
        Principal = {
          AWS = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
        }
        Action    = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource  = [
          "${aws_s3_bucket.data.arn}",
          "${aws_s3_bucket.data.arn}/*"
        ]
        Condition = {
          IpAddress = {
            "aws:SourceIp": ["10.0.0.0/8"]  # Replace with your allowed IP range
          }
        }
      }
    ]
  })
}

# Secure EC2 instance
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  root_block_device {
    encrypted = true
  }

  vpc_security_group_ids = [aws_security_group.restricted.id]

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"  # Require IMDSv2
  }

  tags = {
    Name = "SecureWebServer"
  }
}

# Restricted security group
resource "aws_security_group" "restricted" {
  name        = "restricted_access"
  description = "Allow specific inbound traffic"

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Replace with your allowed IP range
  }

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Replace with your allowed IP range
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "restricted_access"
  }
}

# Secure RDS instance
resource "aws_db_instance" "default" {
  identifier           = "secure-db"
  allocated_storage    = 20
  max_allocated_storage = 100  # Enable storage autoscaling
  storage_type         = "gp3"  # Use newer GP3 for better performance and cost
  engine              = "mysql"
  engine_version      = "8.0"
  instance_class      = "db.t3.micro"
  
  # Security configurations
  username            = var.db_username  # Use variable for username
  password            = var.db_password
  publicly_accessible = false
  storage_encrypted   = true
  kms_key_id         = aws_kms_key.db_encryption_key.arn  # Use custom KMS key
  
  # Backup and maintenance
  backup_retention_period = 30  # Increased retention period
  backup_window          = "03:00-04:00"
  maintenance_window     = "Mon:04:00-Mon:05:00"
  skip_final_snapshot    = false
  final_snapshot_identifier = "${var.environment}-final-snapshot"
  copy_tags_to_snapshot  = true
  delete_automated_backups = false
  
  # High availability
  multi_az             = true
  
  # Network security
  vpc_security_group_ids = [aws_security_group.db_restricted.id]
  db_subnet_group_name   = aws_db_subnet_group.database.id

  # Enhanced monitoring
  monitoring_interval = 30
  monitoring_role_arn = aws_iam_role.rds_monitoring_role.arn
  
  # Performance insights
  performance_insights_enabled = true
  performance_insights_retention_period = 7
  performance_insights_kms_key_id = aws_kms_key.performance_insights.arn
  
  # Enable deletion protection
  deletion_protection = true

  # Parameter group with security settings
  parameter_group_name = aws_db_parameter_group.secure_mysql.name
  
  # Enable automatic minor version upgrades
  auto_minor_version_upgrade = true

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
    Backup      = "true"
    Encryption  = "true"
  }
}

# Create KMS key for RDS encryption
resource "aws_kms_key" "db_encryption_key" {
  description             = "KMS key for RDS database encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  tags = {
    Environment = var.environment
    Purpose     = "rds-encryption"
  }
}

# Create KMS key for Performance Insights
resource "aws_kms_key" "performance_insights" {
  description             = "KMS key for RDS Performance Insights"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  tags = {
    Environment = var.environment
    Purpose     = "performance-insights"
  }
}

# Create a secure parameter group
resource "aws_db_parameter_group" "secure_mysql" {
  family = "mysql8.0"
  name   = "secure-mysql-${var.environment}"

  parameter {
    name  = "require_secure_transport"
    value = "ON"
  }
  
  parameter {
    name  = "slow_query_log"
    value = "1"
  }

  parameter {
    name  = "long_query_time"
    value = "2"
  }

  parameter {
    name  = "log_output"
    value = "FILE"
  }
}

# Create DB subnet group
resource "aws_db_subnet_group" "database" {
  name       = "database-${var.environment}"
  subnet_ids = var.database_subnet_ids  # You'll need to provide private subnet IDs

  tags = {
    Environment = var.environment
  }
}

# Create IAM role for enhanced monitoring
resource "aws_iam_role" "rds_monitoring_role" {
  name = "rds-monitoring-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring_policy" {
  role       = aws_iam_role.rds_monitoring_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# DB security group
resource "aws_security_group" "db_restricted" {
  name        = "db_restricted_access"
  description = "Allow database access from web tier"

  ingress {
    description     = "MySQL"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.restricted.id]
  }
}

# Least privilege IAM role
resource "aws_iam_role" "web_role" {
  name = "web_server_role"

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

resource "aws_iam_role_policy" "web_policy" {
  name = "web_server_policy"
  role = aws_iam_role.web_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.data.arn,
          "${aws_s3_bucket.data.arn}/*"
        ]
      }
    ]
  })
}