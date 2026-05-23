## Lab Completion Report: Identifying AWS Account ID via Public S3 Bucket

### 1. Discovery & Reconnaissance

I initiated the engagement by performing an **nmap** scan on the target IP address to identify open ports and services associated with the host.

Bash

```
nmap -sV <TARGET_IP>
```

After identifying the web service, I navigated to the site and inspected the page source. I located a static image asset hosted on Amazon S3, which revealed the target bucket name: `mega-big-tech-assets`.

---

### 2. S3 Bucket Verification

I used the AWS CLI with the `--no-sign-request` flag to confirm that the bucket was publicly accessible and to list its contents.

Bash

```
aws s3 ls s3://mega-big-tech-assets --no-sign-request
```

---

### 3. Account ID Enumeration

To find the 12-digit AWS Account ID, I utilized a side-channel enumeration technique. This method exploits the `s3:ResourceAccount` condition key in IAM policies, which allows for matching account IDs using wildcards.

I automated this process using the `s3-account-search` tool:

1. **Environment Setup:** I cloned the repository and installed the necessary dependencies.
    
2. **Execution:** I ran the search script against the identified bucket.
    

Bash

```
python3 s3-account-search.py mega-big-tech-assets
```

**Result:** The script successfully iterated through the policy evaluations and recovered the Account ID: `123456789012`.

---

### 4. Impact Assessment

By securing the Account ID, I have moved from general reconnaissance to targeted enumeration. I can now attempt to:

- Identify valid IAM roles by guessing common naming patterns (e.g., `admin`, `ReadOnly`).
    
- Search for public EBS or RDS snapshots specifically filtered by this Account ID, increasing the likelihood of finding sensitive data backups.
    

---

### 5. Remediation Recommendations

- **Enable S3 Block Public Access:** This should be applied at the account level to prevent accidental exposure.
    
- **Restrict Bucket Policies:** Use specific IAM principals rather than wildcards and avoid exposing assets that do not strictly require public access.
