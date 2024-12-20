# Features
### Ram Account
- Grant & Revoke single permission to RAM account
- Grant & Revoke multiple permission to RAM account
- Grant & Revoke single permission to RAM account CROSS
- Grant & Revoke multiple permission to RAM account CROSS

### RAM Role
- Grant & Revoke single permission to RAM role
- Grant & Revoke multiple permission to RAM role
- Grant & Revoke single permission to RAM role CROSS
- Grant & Revoke multiple permission to RAM role CROSS

# Policy Requirements For Each Provider
### Standalone RAM Account
- Custom Policy
```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ram:ListPolicies",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "ram:AttachPolicyToUser",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "ram:DetachPolicyFromUser",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "ram:AttachPolicyToRole",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "ram:DetachPolicyFromRole",
      "Resource": "*"
    }
  ]
}
```

### Controller RAM Account
- Custom Policy
```json
{
  "Version": "1",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
```

### Role That Will Be Assumed by Controller RAM Account
-  Trust Policy
```json
{
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Effect": "Allow",
      "Principal": {
        "RAM": [
          "acs:ram::{CONTROLLER_MAIN_ACCOUNT_ID}:root"
        ]
      }
    }
  ],
  "Version": "1"
}
```

- Custom Policy
```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ram:ListPolicies",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "ram:AttachPolicyToUser",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "ram:DetachPolicyFromUser",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "ram:AttachPolicyToRole",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "ram:DetachPolicyFromRole",
      "Resource": "*"
    }
  ]
}
```

# Standard For Each Provider Creation
### For Standalone Provider
```json
{
  "type": "alicloud_ram",
  "urn": "al-xxxx-id-x:500xxxxxxxxxxxxx", // using self main account id
  "allowed_account_types": [
    "ramUser",
    "ramRole"
  ],
  "credentials": {
    "main_account_id": "500xxxxxxxxxxxxx", // using self main account id
    "access_key_id": "access_key_id (in base64)",
    "access_key_secret": "access_key_secret (in base64)",
  },
  "appeal": {
    "allow_permanent_access": false,
    "allow_active_access_extension_in": "336h"
  },
  "resources": [
    {
      "type": "account",
      "policy": {
        "id": "alicloud_account_policy",
        "version": 1
      },
      "roles": [
        {
          "id": "sample-role",
          "name": "Sample Role",
          "description": "Description for Sample Role",
          "permissions": [
            {
              "name": "AliyunOSSReadOnlyAccess",
              "type": "System"
            },
            {
              "name": "AliyunOSSFullAccess",
              "type": "System"
            },
            {
              "name": "AliyunECSFullAccess",
              "type": "System"
            }
          ]
        },
        {
          "id": "sample-role-2",
          "name": "Sample Role 2",
          "description": "Description for Sample Role 2",
          "permissions": [
            {
              "name": "AliyunCloudMonitorFullAccess",
              "type": "System"
            }
          ]
        }
      ]
    }
  ]
}
```

### For CROSS Provider
```json
{
  "type": "alicloud_ram",
  "urn": "al-xxxx-id-x:501xxxxxxxxxxxxx", // using role main account id
  "allowed_account_types": [
    "ramUser",
    "ramRole"
  ],
  "credentials": {
    "main_account_id": "501xxxxxxxxxxxxx", // using role main account id
    "access_key_id": "access_key_id (in base64)",
    "access_key_secret": "access_key_secret (in base64)",
    "ram_role": "acs:ram::501xxxxxxxxxxxxx:role/role-name" // using role main account id
  },
  "appeal": {
    "allow_permanent_access": false,
    "allow_active_access_extension_in": "336h"
  },
  "resources": [
    {
      "type": "account",
      "policy": {
        "id": "alicloud_account_policy",
        "version": 1
      },
      "roles": [
        {
          "id": "sample-role",
          "name": "Sample Role",
          "description": "Description for Sample Role",
          "permissions": [
            {
              "name": "AliyunOSSReadOnlyAccess",
              "type": "System"
            },
            {
              "name": "AliyunOSSFullAccess",
              "type": "System"
            },
            {
              "name": "AliyunECSFullAccess",
              "type": "System"
            }
          ]
        },
        {
          "id": "sample-role-2",
          "name": "Sample Role 2",
          "description": "Description for Sample Role 2",
          "permissions": [
            {
              "name": "AliyunCloudMonitorFullAccess",
              "type": "System"
            }
          ]
        }
      ]
    }
  ]
}
```

# Example Requests
### Create Appeal For RAM Account
```json
{
  "resources": [
    {
      "id": "{{RESOURCE_ID}}",
      "role": "sample-role",
      "options": {
        "duration": "1h"
      },
      "details": {
        "questions": {
          "What is the purpose of getting access to this role?": "Test"
        }
      }
    }
  ],
  "account_id": "example.user@500xxxxxxxxxxxxx.onaliyun.com",
  "account_type": "ramUser"
}
```

### Create Appeal For RAM Role
```json
{
  "resources": [
    {
      "id": "{{RESOURCE_ID}}",
      "role": "sample-role",
      "options": {
        "duration": "1h"
      },
      "details": {
        "questions": {
          "What is the purpose of getting access to this role?": "Test"
        }
      }
    }
  ],
  "account_id": "role-name",
  "account_type": "ramRole"
}
```

# DOCS
For another documentation you can refer to this link:
[https://github.com/goto/guardian/tree/main/plugins/providers/alicloud_ram/docs](https://github.com/goto/guardian/tree/main/plugins/providers/alicloud_ram/docs)

