#describing provider
provider "aws" {
   region = "ap-south-1"
   access_key = "AK***************NLU"  
  secret_key = "R2***********************************Dn+"
 }

variable "vpc" {
	type = string
default = "vpc-e96e8d94"
}


#Creating Key
resource "tls_private_key" "tls_key" {
  algorithm = "RSA"
}


#Generating Key-Value Pair
resource "aws_key_pair" "mykey" {
  key_name   = "zoomkey"
  public_key = "${tls_private_key.tls_key.public_key_openssh}"
}


resource "aws_security_group" "morning-ssh-http" {
  name        = "morning-ssh-http"
  description = "allow ssh and http traffic"


  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }




  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}




#Creating a S3 Bucket
resource "aws_s3_bucket" "web-bucket" {
  bucket = "my-web-static-data-buckett"
  acl    = "public-read"
}


#Putting Objects in S3 Bucket
resource "aws_s3_bucket_object" "web-object1" {
  bucket = "${aws_s3_bucket.web-bucket.bucket}"
  key    = "image.png"
  source = "image.png"
  acl    = "public-read"
}


#Creating CloutFront with S3 Bucket Origin
resource "aws_cloudfront_distribution" "s3-web-distribution" {
  origin {
    domain_name = "${aws_s3_bucket.web-bucket.bucket_regional_domain_name}"
    origin_id   = "${aws_s3_bucket.web-bucket.id}"
  }


  enabled             = true
  is_ipv6_enabled     = true
  comment             = "S3 Web Distribution"


  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${aws_s3_bucket.web-bucket.id}"


    forwarded_values {
      query_string = false


      cookies {
        forward = "none"
      }
    }


    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }


  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["IN"]
    }
  }


  tags = {
    Name        = "Web-CF-Distribution"
    Environment = "Production"
  }


  viewer_certificate {
    cloudfront_default_certificate = true
  }


  depends_on = [
    aws_s3_bucket.web-bucket
  ]
}


resource "aws_instance" "good-morning" {
  ami               = "ami-0447a12f28fddb066"
  instance_type     = "t2.micro"
  availability_zone = "ap-south-1a"
  security_groups   = ["${aws_security_group.morning-ssh-http.name}","default"]
  key_name = "zoomkey"
  user_data = <<-EOF
                #! /bin/bash
                sudo yum install httpd -y
                sudo systemctl start httpd
                sudo systemctl enable httpd
              EOF




  tags = {
        Name = "webserver"
  }


}





//EFS-----------------------

data "aws_subnet_ids" "subnet" {
  vpc_id = var.vpc
}

data "aws_subnet" "subnets" {
  for_each = data.aws_subnet_ids.subnet.ids
  id       = each.value

  depends_on = [
    data.aws_subnet_ids.subnet
  ]
}


//Creating Security Group For EFS
resource "aws_security_group" "efs-sg" {
  name        = "efs-sg"
  description = "EFS SG"
  vpc_id      = var.vpc

  //Adding Rules to Security Group 
  ingress {
    description = "NFS Rule"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    security_groups = ["${aws_security_group.morning-ssh-http.id}"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_efs_file_system" "file_system" {
  creation_token = "web-efs"

  depends_on = [
    aws_instance.good-morning
  ]
}

  resource "aws_efs_file_system_policy" "efs-policy" {
   file_system_id = "${aws_efs_file_system.file_system.id}"

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Id": "efs-policy-wizard-eda0b278-4348-4642-b4c9-490bbf334873",
    "Statement": [
        {
            "Sid": "efs-statement-c7a84ce0-72a9-420a-bea0-84194267aeff",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": [
                "elasticfilesystem:ClientMount",
                "elasticfilesystem:ClientWrite",
                "elasticfilesystem:ClientRootAccess"
            ]
        }
    ]
}
POLICY
}

resource "aws_efs_mount_target" "mnt_trgt" {
  file_system_id  = "${aws_efs_file_system.file_system.id}"
  subnet_id       = [for s in data.aws_subnet.subnets : s.id if s.availability_zone == "ap-south-1a"].0
  security_groups = ["${aws_security_group.efs-sg.id}"]

 
    provisioner "remote-exec" {
  connection {
    agent       = "false"
  type        = "ssh"
      user        = "ec2-user"
   private_key = "${tls_private_key.tls_key.private_key_pem}"
     host        = "${aws_instance.good-morning.public_ip}"
    }
    
    inline = [
      "sudo mount ${aws_efs_file_system.file_system.dns_name}:/ /var/www/html/",
      "touch /var/www/html/index.html",
      "echo '<h1>Sample Webserver Network Nuts </h1><br>' > /var/www/html/index.html",
      "echo '<img src=\"http://${aws_cloudfront_distribution.s3-web-distribution.domain_name}/image.png\">' >> /var/www/html/index.html",
    ]
  }

  depends_on = [
   aws_efs_file_system.file_system
  ]
}

output "depended_on" {
  value = "${aws_efs_mount_target.mnt_trgt.id}"

  depends_on = [
    aws_efs_mount_target.mnt_trgt,
  ]
}

resource "null_resource" "chrome" {
provisioner "local-exec" {
 command = "start chrome ${aws_instance.good-morning.public_ip}/index.html"

}

  depends_on = [
    aws_efs_mount_target.mnt_trgt,
  ]


}


