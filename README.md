# Tekton Dashboard Authentication Proxy

This project provides an authentication and authorization proxy for the Tekton Dashboard, enabling Azure Active Directory (Azure AD) integration with group-based access control.

## Overview

The Tekton Dashboard Authentication Proxy sits in front of your Tekton Dashboard and:

1. Authenticates users via Azure AD
2. Authorizes users based on their Azure AD group memberships
3. Proxies authenticated requests to the Tekton Dashboard
4. Sets Kubernetes impersonation headers based on the user's identity and group memberships


## Features

- **Azure AD Integration**: Secure authentication using your organization's Azure AD tenant
- **Group-based Authorization**: Control access based on Azure AD group memberships
- **Kubernetes RBAC Integration**: Maps Azure AD groups to Kubernetes RBAC roles
- **Session Management**: Secure cookie-based sessions with configurable expiration
- **Kubernetes Impersonation**: Sets appropriate impersonation headers for Kubernetes API requests
- **Easy Deployment**: Helm chart for Kubernetes deployment

## Prerequisites

- A Kubernetes cluster with Tekton Dashboard installed
- An Azure AD tenant with administrator access
- Docker and kubectl CLI tools for development
- Helm for deployment

## Quick Start

### 1. Set Up Azure AD Application

1. Log in to the Azure Portal
2. Navigate to Azure Active Directory → App registrations
3. Click "New registration"
4. Enter a name for your application (e.g., "Tekton Dashboard Auth")
5. Set the redirect URI to `https://your-tekton-dashboard-domain/callback`
6. Click "Register"
7. Note the "Application (client) ID" and "Directory (tenant) ID"
8. Under "Certificates & secrets," create a new client secret and note its value
9. Under "API permissions," add the following permissions:
   - Microsoft Graph API → User.Read
   - Microsoft Graph API → GroupMember.Read.All
   - OpenID permissions → email
   - OpenID permissions → openid
   - OpenID permissions → profile
10. Grant admin consent for these permissions

### 2. Deploy Using Helm

1. Clone this repository:
   ```
   git clone # TODO
   cd tekton-dashboard-auth
   ```

2. Update a `values.yaml` file with your configuration:
   ```yaml
    appName: tekton-dashboard-auth
    image:
      name: yourdockerrepo/tekton-dashboard-auth
      tag: latest
      pullPolicy: Always
      imagePullSecret: your-pull-secret
    resources:
      requests:
        cpu: 5m
        memory: 64Mi
      limits:
        cpu: 50m
        memory: 128Mi
    replicas: 1
    ingress:
      enabled: true
      className: nginx-internal
      annotations:
        cert-manager.io/cluster-issuer: letsencrypt-dns01
        nginx.ingress.kubernetes.io/ssl-redirect: "true"
      host: tekton.your-domain.com
    service:
      port: 8080
    envVars:
      # Azure AD Configuration
      AZURE_TENANT_ID: your-tenant-id
      AZURE_CLIENT_ID: your-client-id
      # General Configuration
      REDIRECT_URL: https://tekton.your-domain.com/callback
      TEKTON_DASHBOARD_URL: http://tekton-dashboard.tekton-pipelines.svc.cluster.local:9097
      # Authorization Configuration
      # Comma-separated list of Azure AD group IDs or display names that are allowed to access Tekton Dashboard
      ALLOWED_GROUPS: your-azure-group1,your-azure-group2
    secrets:
      # Azure AD Configuration
      AZURE_CLIENT_SECRET: your-client-secret
      # General Configuration
      COOKIE_SECRET: your-random-cookie-secret
    rbac:
      # Enable or disable RBAC setup
      enabled: true
      # Groups with admin access across all namespaces
      adminGroups:
        - "your-admin-group"
      # Groups with read-only access across all namespaces
      globalViewerGroups:
        - "your-viewer-group"
      # Namespace-specific access
      namespaces:
        tekton-pipelines:
          readWriteGroups:
            - "your-developer-group"
        test-namespace:
          readOnlyGroups:
            - "your-pm-group"
   ```

3. Install the Helm chart:
   ```
   helm install tekton-dashboard-auth ./deploy -f ./deploy/values.yaml
   ```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Port the server will listen on | `8080` |
| `TEKTON_DASHBOARD_URL` | URL of the Tekton Dashboard service | `http://localhost:9097` |
| `COOKIE_SECRET` | Secret used to sign session cookies | `change-me-in-production` |
| `AZURE_TENANT_ID` | Azure AD tenant ID | Required |
| `AZURE_CLIENT_ID` | Azure AD client application ID | Required |
| `AZURE_CLIENT_SECRET` | Azure AD client secret | Required |
| `REDIRECT_URL` | OAuth2 callback URL | `http://localhost:8080/callback` |
| `ALLOWED_GROUPS` | Comma-separated list of Azure AD group IDs or display names that are allowed to access | Required |

### RBAC Configuration

The Helm chart can optionally create and configure Kubernetes RBAC resources to control access to Tekton resources based on Azure AD group memberships. This feature can be enabled or disabled using the `rbac.enabled` flag in your values file.

#### RBAC Structure

The Helm chart creates several ClusterRoles with different permission levels:

1. **tekton-dashboard-basic-viewer**: Basic permissions to view Kubernetes resources
   - Provides read-only access to core Kubernetes resources (namespaces, pods, services, etc.)
   - All authenticated users receive these permissions

2. **tekton-dashboard-resources-viewer**: Permissions to view Tekton resources
   - Provides read-only access to Tekton resources (pipelines, tasks, runs, etc.)
   - Assigned to groups specified in `globalViewerGroups` and `namespaces.[namespace].readOnlyGroups`

3. **tekton-dashboard-resources-editor**: Permissions to edit Tekton resources
   - Provides read/write access to Tekton resources (create/update pipelines, tasks, runs, etc.)
   - Assigned to groups specified in `namespaces.[namespace].readWriteGroups`

4. **tekton-dashboard-admin**: Full administrative permissions for Tekton resources
   - Provides full CRUD access to all Tekton resources across all namespaces
   - Assigned to groups specified in `adminGroups`

These roles are bound to your Azure AD groups based on the configuration in `values.yaml`. When a user authenticates, their Azure AD group memberships are retrieved and mapped to Kubernetes groups via impersonation headers, allowing the Kubernetes RBAC system to enforce appropriate permissions.

#### RBAC Configuration Example

```yaml
rbac:
  # Enable RBAC setup - set to false to disable
  enabled: true
  
  # Cluster-wide admin groups - full access to all Tekton resources
  adminGroups:
    - "tekton-admins"
  
  # Cluster-wide viewer groups - read-only access to all Tekton resources
  globalViewerGroups:
    - "tekton-viewers"
  
  # Namespace-specific access configuration
  namespaces:
    # For the "development" namespace
    development:
      # Read-write access to Tekton resources in this namespace
      readWriteGroups:
        - "dev-team"
    
    # For the "production" namespace
    production:
      # Read-only access to Tekton resources in this namespace
      readOnlyGroups:
        - "qa-team"
      # Read-write access to Tekton resources in this namespace
      readWriteGroups:
        - "release-team"
```

#### Disabling RBAC

If you prefer to manage RBAC separately or use a different authorization mechanism, you can disable the built-in RBAC setup:

```yaml
rbac:
  enabled: false
```

When RBAC is disabled, the proxy will still authenticate users via Azure AD and check if they belong to the allowed groups, but no Kubernetes RBAC resources will be created or modified.


## Authentication Flow

### 1. User Accesses the Tekton Dashboard URL
- The user navigates to the protected Tekton Dashboard route served by the authentication proxy.

### 2. Redirect to Azure AD Login (if Unauthenticated)
- If the user does not have a valid session, they are redirected to the **Microsoft Azure Active Directory (Azure AD)** login page via the **OAuth2** flow.

### 3. Azure AD Authentication and Group Retrieval
- After successful authentication, the proxy performs the following:
  1. Verifies the **ID token** using **OIDC** (OpenID Connect).
  2. Calls the **Microsoft Graph API** to retrieve the user’s **group memberships** using the `/me/memberOf` endpoint.
  3. Checks if the user belongs to any of the **allowed groups** (by **group ID** or **display name**) configured in the system.

### 4. Access Decision
- If the user is a member of an allowed group, they are **authorized** and granted access.
- If the user is not in an allowed group, the request is denied with a **403 Forbidden** response.

### 5. Session Creation and Identity Mapping
- On successful authorization:
  - The **user’s email** and **group display names** are stored in the session.
  - The session also includes an **expiration timestamp** to enforce **reauthentication** after a set duration (e.g., 8 hours).

### 6. Kubernetes Impersonation Setup (Core of Authorization)
- Each authenticated and authorized request to the Tekton Dashboard is **proxied with Kubernetes impersonation headers**. These headers are critical for passing the identity and authorization context to Kubernetes (or Tekton) for RBAC evaluation.

  **Headers Set for Kubernetes Impersonation:**

  | Header                | Value                      | Purpose                                                                                   |
  |-----------------------|----------------------------|-------------------------------------------------------------------------------------------|
  | `Impersonate-User`     | `<user email>`             | Tells Kubernetes to treat the request as coming from the specified user.                  |
  | `Impersonate-Group`    | `<group name>` (one per group) | Declares group membership for the user in the context of Kubernetes RBAC. Multiple headers are set for multiple groups. |

  - The **`Impersonate-User`** header ensures the request is processed as if it came from the **actual authenticated user**.
  - The **`Impersonate-Group`** headers (one for each group the user belongs to) allow Kubernetes to evaluate **role-based access** (RBAC) based on group membership.

### 7. Request Proxied to Tekton Dashboard
- After setting the Kubernetes impersonation headers, the request is forwarded to the actual Tekton Dashboard.
- The Tekton Dashboard itself remains unaware of the underlying authentication mechanism—**Kubernetes performs the authorization** based on the impersonation headers set by the proxy.


## Development

### Building the Application

1. Clone the repository
2. Install dependencies:
   ```
   go mod download
   ```
3. Build the application:
   ```
   go build -o tekton-dashboard-auth .
   ```

### Running Locally

1. Create a `.env` file with your configuration:
   ```
   PORT=8080
   TEKTON_DASHBOARD_URL=http://localhost:9097
   COOKIE_SECRET=your-cookie-secret
   AZURE_TENANT_ID=your-tenant-id
   AZURE_CLIENT_ID=your-client-id
   AZURE_CLIENT_SECRET=your-client-secret
   REDIRECT_URL=http://localhost:8080/callback
   ALLOWED_GROUPS=your-azure-group1,your-azure-group2
   ```

2. Run the application:
   ```
   ./tekton-dashboard-auth
   ```

### Building Docker Image

```
docker build -t yourdockerrepo/tekton-dashboard-auth:latest .
docker push yourdockerrepo/tekton-dashboard-auth:latest
```

## Security Considerations

- Use HTTPS for all external endpoints
- Generate a strong random string for `COOKIE_SECRET`
- Use a dedicated Azure AD application with minimal permissions
- Review and limit the RBAC permissions granted to each group
- Run the container as a non-root user (configured in the Dockerfile)

## Troubleshooting

### Common Issues

1. **Authentication Failed**: Verify your Azure AD configuration, especially the client ID, tenant ID, and client secret.

2. **Authorization Failed**: Check that:
   - The user is a member of one of the allowed groups
   - The group ID or display name matches exactly what's configured in `ALLOWED_GROUPS`
   - The Microsoft Graph API permissions have been granted

3. **Proxy Connection Failed**: Ensure the Tekton Dashboard URL is correct and accessible from the proxy pod.


## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request


## Acknowledgements

- [Tekton Dashboard](https://github.com/tektoncd/dashboard)
