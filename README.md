# Accessing Google Workspace without Domain Wide Delegation

This method assumes you are going to set-up this access without using Domain Wide Delegation. To understand why Domain Wide Delegation should be avoided see Security Benefits of OAuth over Service Accounts 

In this scenario we are setting up API access to Google Vault and the Google Workspace Directory to get a list of mailboxes on litigation hold. 

### AD
In our case we have a Google mailbox with an Active Directory backed account. This has been syn'd into Google. This will be used to login and approve consent with the following set-up:

Located in the OU Exchange Shared Mailboxes


### Entra
This service account is added to the Users and Groups granted access to the Enterprise App ‘Google Workspace’
 

### GCP

A project should be created.

The Application Configuration will be done from the GCP console. Google Cloud console 

A Compute Engine Default Service Account may be created by Google on project creation (it depends on when you set-up your Google account, as this is no longer default behaviour) and assigned as Editor to the GCP project. We don’t need this but we don’t have permission to remove the Editor rights. However, the API access for this account can be removed.

Before you can configure API access you need to enable the API on the project. In this case we enable the Admin SDK API and the Google Vault API.

Configure the application as follows

OAuth Consent: User Type: Internal

App Name: Litigation Hold Viewer

Authorized Domain: yourgoogledomain.io

#### Permissions

- APIs

    - Google Vault API
    - Admin SDK API

- Scopes

````
.../auth/ediscovery.readonly

.../auth/admin.directory.user.readonly
````

Create an OAuth Client in the project

Type: Web Application

Name: oauth-client-vault-readonly

Redirect URI: http://localhost:65432/
 


### Google Workspace
A custom role added in Google Workspace
- Legal Hold Viewer

Legal Hold Viewer contains the privileges:

#### Google Vault
- View All Matters
- Access All Logs
- Manage Audits

#### Organizational Units

- Read

[See Google Vault Help](https://support.google.com/vault/answer/2799699?hl=en#reference)

A custom role added in Google Workspace
- Admin API Users Read

Admin API Users Read contains the privileges:

- Admin API
- Users Read

The AD service account which consented to the application is assigned to the Custom Role ‘Admin API Users Read’

The AD service account which consented to the application is assigned to the Custom Role ‘Legal Hold Viewer’

Run the code and authenticate with OAuth ClientID & client secret

Fire up a listener on the redirect URI and ingest this returned code

Send the code, scopes, prompts set to consent and to get a refresh token in addition to an access token set access type to offline

    $query["response_type"] = "code"
    $query["scope"] =  "https://www.googleapis.com/auth/ediscovery.readonly https://www.googleapis.com/auth/admin.directory.user.readonly"
    $query["prompt"] = "consent"
    $query["access_type"] = "offline"
    
On Consent page choose the AD Service Account and Allow

Store the refresh token for future calls of the code

Make your API calls with the refresh token

 

### Running the Code
Once you have your refresh token you can call the APIs. You must call both the Google Vault and Admin SDK APIs as the Google Vault API will not return accounts that are covered by an org unit hold.

The following APIs cover this methods:
 
- List Matters (Google Vault API)
- List Holds in a Matter (Google Vault API)
- List individually specified accounts in a Hold 
- List accounts in an OU where a Litigation Hold is applied (Admin SDK API)

