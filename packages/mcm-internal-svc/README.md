# Internal MCM (Mojaloop Certificate Management) SVC

This internal API service is responsible for managing the public certificates.

Default port: 3200

## Environment Variables

The service can be configured using the following environment variables:

| Variable                   | Description                            | Default Value                                  | Notes                                                                                                                                 |
| -------------------------- | -------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `MONGO_URL`                | URL for connecting to MongoDB.         | `mongodb://root:mongoDbPas42@localhost:27017/` | Update as needed for your MongoDB setup. Default Credentials are from `https://github.com/mojaloop/platform-shared-tools`             |
| `PRODUCTION_MODE`          | Toggles the production mode.           | `false`                                        | Set to `true` in production environments.                                                                                             |
| `LOG_LEVEL`                | Defines the logging level.             | `DEBUG`                                        | Acceptable values are defined in [LogLevel](https://github.com/mojaloop/logging-bc/blob/main/packages/public-types-lib/src/index.ts). |
| `KAFKA_URL`                | URL for connecting to Kafka.           | `localhost:9092`                               | Update as needed for your Kafka setup.                                                                                                |
| `KAFKA_LOGS_TOPIC`         | Kafka topic for logs.                  | `logs`                                         | Change if a different topic is used for logs.                                                                                         |
| `SERVICE_START_TIMEOUT_MS` | Service start timeout in milliseconds. | `60000`                                        | Modify based on service start-up time requirements.                                                                                   |
| `SVC_HTTP_PORT`            | HTTP port for the service.             | `3200`                                         | Override if a different port is required.                                                                                             |

## Build

```bash
npm run build
```

## Run this service

Anywhere in the repo structure:

```bash
npm run start:dev
```

## Auto build (watch)

```bash
npm run watch
```

## Unit Tests

```bash
npm run test:unit
```

## Integration Tests

```bash
npm run test:integration
```
