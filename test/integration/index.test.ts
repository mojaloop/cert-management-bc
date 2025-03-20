/*****
License
--------------
Copyright © 2020-2025 Mojaloop Foundation
The Mojaloop files are made available by the Mojaloop Foundation under the Apache License, Version 2.0 (the "License") and you may not use these files except in compliance with the License. You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, the Mojaloop files are distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

Contributors
--------------
This is the official list of the Mojaloop project contributors for this file.
Names of the original copyright holders (individuals or organizations)
should be listed with a '*' in the first column. People who have
contributed from an organization can be listed under the organization
that actually holds the copyright for their contributions (see the
Mojaloop Foundation for an example). Those individuals should have
their names indented and be marked with a '-'. Email address can be added
optionally within square brackets <email>.

* Mojaloop Foundation
- Name Surname <name.surname@mojaloop.io>

* Crosslake
- Pedro Sousa Barreto <pedrob@crosslaketech.com>

* ThitsaWorks
- Si Thu Myo <sithu.myo@thitsaworks.com>
*****/

"use strict";

import { ILogger, LogLevel } from "@mojaloop/logging-bc-public-types-lib";
import { CertificatesInternalHttpClient } from "../../packages/client-internal-lib/src";
import { AuthenticatedHttpRequester } from "@mojaloop/security-bc-client-lib";
import { ConsoleLogger } from "@mojaloop/logging-bc-public-types-lib";

/* ********** Constants Begin ********** */

// General:
// const BOUNDED_CONTEXT_NAME: string = "mcm-bc";
// const SERVICE_NAME: string = "integration-tests";
// const SERVICE_VERSION: string = "0.0.1";

// Logging:
// const LOGGING_LEVEL: LogLevel = LogLevel.INFO;
// const LOGGING_TOPIC: string = `${BOUNDED_CONTEXT_NAME}_${SERVICE_NAME}_logging`;

// Web server:
const BASE_URL_PARTICIPANTS_HTTP_SERVICE: string = `http://localhost:3200`;

/* ********** Constants End ********** */

let logger: ILogger;
let certificatesInternalHttpClient: CertificatesInternalHttpClient;
let authenticatedHttpRequester: AuthenticatedHttpRequester;

const AUTH_N_SVC_BASEURL =
    process.env["AUTH_N_SVC_BASEURL"] || "http://localhost:3201";
const AUTH_N_SVC_TOKEN_URL = AUTH_N_SVC_BASEURL + "/token";

const CLIENT_ID = "security-bc-ui";
const USERNAME = "user";
const PASSWORD = "superPass";

describe("certificates management - integration tests", () => {
    beforeAll(async () => {
        // Setup
        console.log(
            `Integration tests for endpoint: ${BASE_URL_PARTICIPANTS_HTTP_SERVICE}`
        );
        logger = new ConsoleLogger();

        authenticatedHttpRequester = new AuthenticatedHttpRequester(
            logger,
            AUTH_N_SVC_TOKEN_URL
        );
        authenticatedHttpRequester.setUserCredentials(
            CLIENT_ID,
            USERNAME,
            PASSWORD
        );

        certificatesInternalHttpClient = new CertificatesInternalHttpClient(
            logger,
            BASE_URL_PARTICIPANTS_HTTP_SERVICE,
            authenticatedHttpRequester
        );
    });

    afterAll(async () => {
        // Cleanup
    });

    test("list certificates", async () => {
        const certs = await certificatesInternalHttpClient.getListCertificates();
        expect(certs).toBeInstanceOf(Array);
    });

    test("create certificate using string", async () => {
        const certId = "test_cert_1";
        const cert_string = "---- BEGIN CERTIFICATE ----\n"+ "testing testing" +"----- END CERTIFICATE -----";
        const status = await certificatesInternalHttpClient.postCertificate(certId, cert_string);

        expect(status).toBeDefined();
        expect(status).toBe(200);

        // cleanup
        await certificatesInternalHttpClient.deleteCertificate(certId);
    })

    test("get certificate", async () => {
        const certId = "test_cert_2";
        const cert_string = "---- BEGIN CERTIFICATE ----\n"+ "testing testing" +"----- END CERTIFICATE -----";
        const status = await certificatesInternalHttpClient.postCertificate(certId, cert_string);

        expect(status).toBeDefined();
        expect(status).toBe(200);

        const cert = await certificatesInternalHttpClient.getCertificate(certId);
        expect(cert).toBeDefined();
        expect(cert).toBe(cert_string);

        // cleanup
        await certificatesInternalHttpClient.deleteCertificate(certId);
    })

    test("delete certificate", async () => {
        const certId = "test_cert_3";
        const cert_string = "---- BEGIN CERTIFICATE ----\n"+ "testing testing" +"----- END CERTIFICATE -----";
        const status = await certificatesInternalHttpClient.postCertificate(certId, cert_string);

        expect(status).toBeDefined();
        expect(status).toBe(200);

        const delete_status = await certificatesInternalHttpClient.deleteCertificate(certId);
        expect(delete_status).toBeDefined();
        expect(delete_status).toBe(200);
    })

    test("get certificate - not found", async () => {
        const certId = "test_cert_999";
        const cert = await certificatesInternalHttpClient.getCertificate(certId);
        expect(cert).toBeNull();
    })
});
