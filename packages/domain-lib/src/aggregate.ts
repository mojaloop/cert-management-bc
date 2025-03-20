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
import { IConfigurationClient } from "@mojaloop/platform-configuration-bc-public-types-lib";
import { IMessageProducer } from "@mojaloop/platform-shared-lib-messaging-types-lib";
import path from "path";
import fs from "fs";
import {
    CertNotFoundError,
    CertReadingError,
    CertStoringError,
} from "./errors";
import {ICertRepo} from "./interface/infrastructure";
import {ICertificate} from "./types";

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

    // We don't need this function for now
    // public async listCertificates(): Promise<string[]> {
    //     try {
    //         const files = await fs.promises.readdir(this._cert_dir);
    //         const certs = files.map((file) => {
    //             const participantId = file.split("-pub.")[0];
    //             return participantId;
    //         });
    //         return certs;
    //
    //     } catch (error: unknown) {
    //         const errMsg = `Error Listing Certificates: ${(error as Error).message}`;
    //         this._logger.error(errMsg);
    //         throw new CertReadingError(errMsg);
    //     }
    // }

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
    //
    // public async storeCertificate(participantId: string, cert: string): Promise<void> {
    //     try {
    //         await fs.promises.writeFile(filePath, cert);
    //
    //         // const certCreatedPayload: CertCreatedEvtPayload = {
    //         //     participantId: participantId,
    //         // };
    //         // const event = new CertCreatedEvt(certCreatedPayload);
    //         // await this._messageProducer.send(event);
    //
    //     } catch (error: unknown) {
    //         const errMsg = `Error Storing certificate: ${(error as Error).message}`;
    //         this._logger.error(errMsg);
    //         throw new CertStoringError("Error Storing Certificate");
    //     }
    // }
    //
    // public async updateCertificate(
    //     participantId: string,
    //     cert: string
    // ): Promise<void> {
    //     if (!this._validateparticipantId(participantId)) {
    //         const errMsg = `Invalid certificate ID: ${participantId}`;
    //         this._logger.error(errMsg);
    //         throw new participantIdInvalidError(errMsg);
    //     }
    //
    //     const filePath = path.join(this._cert_dir, `${participantId}-pub.pem`);
    //     if (!fs.existsSync(filePath)) {
    //         const errMsg = "Certificate does not exist";
    //         this._logger.error(errMsg);
    //         throw new CertNotFoundError(errMsg);
    //     }
    //
    //     try {
    //         await fs.promises.writeFile(filePath, cert);
    //
    //         // const certChangedPayload: CertChangedEvtPayload = {
    //         //     participantId: participantId,
    //         // };
    //         // const event = new CertChangedEvt(certChangedPayload);
    //         // await this._messageProducer.send(event);
    //
    //     } catch (error: unknown) {
    //         const errMsg = `Error Updating certificate: ${(error as Error).message}`;
    //         this._logger.error(errMsg);
    //         throw new CertStoringError("Error Updating Certificate");
    //     }
    // }
    //
    // public async deleteCertificate(participantId: string): Promise<void> {
    //     if (!this._validateparticipantId(participantId)) {
    //         const errMsg = `Invalid certificate ID: ${participantId}`;
    //         this._logger.error(errMsg);
    //         throw new participantIdInvalidError(errMsg);
    //     }
    //
    //     const filePath = path.join(this._cert_dir, `${participantId}-pub.pem`);
    //     if (!fs.existsSync(filePath)) {
    //         const errMsg = "Certificate does not exist";
    //         this._logger.error(errMsg);
    //         throw new CertNotFoundError(errMsg);
    //     }
    //
    //     try {
    //         await fs.promises.unlink(filePath);
    //
    //         // const certDeletedPayload: CertDeletedEvtPayload = {
    //         //     participantId: participantId,
    //         // };
    //         // const event = new CertDeletedEvt(certDeletedPayload);
    //         // await this._messageProducer.send(event);
    //
    //     } catch (error: unknown) {
    //         const errMsg = `Error Deleting certificate: ${(error as Error).message}`;
    //         this._logger.error(errMsg);
    //         throw new CertStoringError("Error Deleting Certificate");
    //     }
    // }
}
