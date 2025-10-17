# [DEPRECATED] mcm-svc

---------------------------------------------------------------------------------------------------------------------------------------------------------
**Deprecation Notice**: This repo was deprecated as of October 2025. It is no longer maintained, and is no longer referenced by any releases of Mojaloop.

For a list of active Mojaloop repos, please refer to [Mojaloop documentation](https://docs.mojaloop.io) or [Mojaloop GitHub Org](https://github.com/mojaloop).

---------------------------------------------------------------------------------------------------------------------------------------------------------

**EXPERIMENTAL** vNext Mojaloop Certificate Management Service

## Packages

### Certificate Management Service - mcm-svc

#### Workspaces

Check the README.md in each package for configurable environment variables.

- [mcm-internal-svc](./packages/mcm-internal-svc) - Certificate Management API Service for Internal Hub
  - [Internal Management OpenAPI docs](./docs)
- [mcm-external-svc](./packages/mcm-external-svc) - Certificate Providing API Service for External DFSPs Participants
  - [External DFSP OpenAPI docs](./docs)
- [client-external-lib](./packages/client-external-lib) - Client Helper Library for External DFSPs through interop-api-svc
- [client-internal-lib](./packages/client-internal-lib) - Client Helper Library for Internal Hub Services
- [domain-lib](./packages/domain-lib) - Domain Library where all the business logic is implemented

#### External Service Dependencies
<!-- - MongoDB -->
- Kafka (for logger, and event publishing)

See [here](https://github.com/mojaloop/platform-shared-tools/tree/main/packages/deployment/docker-compose-infra)
for more details about how to deploy.

## Usage

### Install NVM - Node version manager

More information on how to install NVM: https://github.com/nvm-sh/nvm

#### Use NVM to install the correct Node.js version

```bash
# (In the repository root directory - one having the .nvmrc file)
nvm install
nvm use
```

### Install Dependencies

All commands below assume you're positioned at the root of the monorepo.

```bash
npm install
```

### Build

```bash
npm run build
```

### Run The MCM Internal Service

```bash
npm run start:mcm-internal-svc
```

### Run The MCM External Service

```bash
npm run start:mcm-external-svc
```

### Unit Tests

```bash
npm run test:unit
```

### Integration Tests

```bash
npm run test:integration
```

### Execute locally the pre-commit checks - these will be executed with every commit and in the default CI/CD pipeline
Make sure these pass before committing any code

```bash
npm run pre_commit_check
```

