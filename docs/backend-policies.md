# Read-only backend credentials (SEC-14)

The proxy only reads from buckets, so give it credentials that can do nothing
else. Uploads (sstate and download tarballs from a trusted CI job) use separate
credentials and don't go through the proxy.

The proxy needs `GetObject` for downloads and `ListBucket` so that a missing
object returns `404` instead of `403`. The bucket connection test in the admin
API and UI also uses `ListBucket`.

## AWS S3 (IAM policy)

Limit to one bucket and, optionally, a prefix:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadObjects",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::acme-yocto-sstate/*"
    },
    {
      "Sid": "ListForNotFound",
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": "arn:aws:s3:::acme-yocto-sstate"
    }
  ]
}
```

With a `prefix:` in the bucket config, restrict both statements to it:
`"Resource": "arn:aws:s3:::acme-yocto-downloads/mirror/*"` for `GetObject`, and
a `"Condition": {"StringLike": {"s3:prefix": ["mirror/*"]}}` on `ListBucket`.

## Cloudflare R2

In the Cloudflare dashboard, go to R2, then **Manage R2 API Tokens**, and create
a token with:

- Permission: **Object Read only**
- Specify bucket(s): only the sstate or download bucket
- TTL: as long as you want to go between rotations

Use the token's Access Key ID and Secret Access Key as the bucket's
`access_key_id` and `secret_access_key` files. The endpoint is
`https://<account-id>.r2.cloudflarestorage.com` and the region is `auto`.

## RustFS and MinIO

Both use S3-style policies. Create a policy, a user for the proxy, and attach
the policy to the user. With the MinIO client (`mc`), which works against
RustFS too:

```sh
cat > yproxy-read.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::yocto-sstate/*"] },
    { "Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::yocto-sstate"] }
  ]
}
JSON
mc alias set local http://rustfs.lan:9000 ADMIN_KEY ADMIN_SECRET
mc admin policy create local yproxy-read yproxy-read.json
mc admin user add local yproxy "$(openssl rand -hex 20)"
mc admin policy attach local yproxy-read --user yproxy
```

Put the user name and password in the proxy's `rustfs_access_key` and
`rustfs_secret_key` secret files.

## Checking it

After starting the proxy, test each bucket from the admin listener:

```sh
curl -X POST -H "Authorization: Bearer $(cat secrets/admin_api_key)" \
  http://localhost:8081/api/v1/buckets/sstate/test
```

A read-only key passes this test. To make sure the key really is read-only, try
an upload with it directly against the backend; it must fail with `AccessDenied`.
