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

* ThitsaWorks
- Si Thu Myo <sithu.myo@thitsaworks.com>
*****/

"use strict";

import { ILogger } from "@mojaloop/logging-bc-public-types-lib";
import { IAuthenticatedHttpRequester } from "@mojaloop/security-bc-public-types-lib";
import {
    UnableToGetCertificateError,
} from "./errors";

export class CertificatesExternalHttpClient {
    // Properties received through the constructor.
    private readonly _logger: ILogger;
    // Other properties.
    private readonly _baseUrlHttpService: string;
    private readonly _authRequester: IAuthenticatedHttpRequester;

    constructor(
        logger: ILogger,
        baseUrlHttpService: string,
        authRequester: IAuthenticatedHttpRequester,
    ) {
        this._logger = logger.createChild(this.constructor.name);
        this._baseUrlHttpService = baseUrlHttpService;
        this._authRequester = authRequester;
    }

    public async getListCertificates(): Promise<string[]> {
        try {
            const url = new URL("/certs", this._baseUrlHttpService).toString();
            const resp = await this._authRequester.fetch(url);

            const respText = await resp.text();

            if (resp.status === 200) {
                return JSON.parse(respText);
            }

            throw new UnableToGetCertificateError();
        } catch (e: unknown) {
            if (e instanceof Error) throw e;
            throw new UnableToGetCertificateError();
        }
    }

    public async getCertificate(certId: string): Promise<string | null> {
        try {
            const url = new URL(
                `/certs/${certId}`,
                this._baseUrlHttpService
            ).toString();
            const resp = await this._authRequester.fetch(url);

            const respText = await resp.text();

            if (resp.status === 200) {
                return respText;
            }

            if (resp.status == 404) {
                return null;
            }

            throw new UnableToGetCertificateError();
        } catch (e: unknown) {
            if (e instanceof Error) throw e;
            throw new UnableToGetCertificateError();
        }
    }
}
