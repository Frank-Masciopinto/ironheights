resource "aws_s3_bucket_policy" "logs_read" {
  bucket = aws_s3_bucket.logs.id
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::210987654321:root" }
      Action    = ["s3:GetObject", "s3:ListBucket"]
      Resource  = ["${aws_s3_bucket.logs.arn}", "${aws_s3_bucket.logs.arn}/*"]
    }]
  })
}
