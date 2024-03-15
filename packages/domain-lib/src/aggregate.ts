/*****
 License
 --------------
 Copyright © 2017 Bill & Melinda Gates Foundation
 The Mojaloop files are made available by the Bill & Melinda Gates Foundation under the Apache License, Version 2.0 (the "License") and you may not use these files except in compliance with the License. You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, the Mojaloop files are distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 Contributors
 --------------
 This is the official list (alphabetical ordering) of the Mojaloop project contributors for this file.
 Names of the original copyright holders (individuals or organizations)
 should be listed with a '*' in the first column. People who have
 contributed from an organization can be listed under the organization
 that actually holds the copyright for their contributions (see the
 Gates Foundation organization for an example). Those individuals should have
 their names indented and be marked with a '-'. Email address can be added
 optionally within square brackets <email>.

 * ThitsaWorks
 - Si Thu Myo <sithu.myo@thitsaworks.com>

 --------------
 ******/

"use strict";

import { ILogger } from "@mojaloop/logging-bc-public-types-lib";
import { IConfigurationClient } from "@mojaloop/platform-configuration-bc-public-types-lib";
import { IMessageProducer } from "@mojaloop/platform-shared-lib-messaging-types-lib";
import {ICertRepo} from "./interface/infrastructure";
import {CertReadingError, ICertificate} from "@mojaloop/cert-management-bc-public-types-lib";

export class CertificateAggregate {
    private _logger: ILogger;
    private _configClient: IConfigurationClient;
    private _messageProducer: IMessageProducer;
    private _cert_dir: string;
    private readonly _certsRepo: ICertRepo;

    constructor(
        configClient: IConfigurationClient,
        messageProducer: IMessageProducer,
        logger: ILogger,
        certsRepo: ICertRepo,
        cert_dir: string
    ) {
        this._configClient = configClient;
        this._messageProducer = messageProducer;
        this._logger = logger.createChild(this.constructor.name);
        this._cert_dir = cert_dir;
        this._certsRepo = certsRepo;
    }

    public async getCertificate(participantId: string): Promise<ICertificate | null> {
        try {
            this._logger.info(`Fetching Certificate [${participantId}]`);
            const cert =  await this._certsRepo.getCertificateByParticipantId(participantId);
            return cert;
        } catch (error: unknown) {
            const errMsg = `Error Certificate Not Found: '${participantId}'`;
            this._logger.error(errMsg);
            throw new CertReadingError(errMsg);
        }
    }
}
