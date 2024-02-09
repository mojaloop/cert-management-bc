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

import express from "express";
import { ILogger } from "@mojaloop/logging-bc-public-types-lib";
import { IConfigurationClient } from "@mojaloop/platform-configuration-bc-public-types-lib";
import { CertificateAggregate, ICertRepo } from "@mojaloop/cert-management-bc-domain-lib";

export class ExpressRoutes {
    private _logger: ILogger;
    private _configClient: IConfigurationClient;
    private _certsAgg: CertificateAggregate;
    private _certsRepo: ICertRepo;

    private _mainRouter = express.Router();

    constructor(
        configClient: IConfigurationClient,
        certsAgg: CertificateAggregate,
        logger: ILogger,
        certsRepo: ICertRepo
    ) {
        this._configClient = configClient;
        this._logger = logger;
        this._certsAgg = certsAgg;
        this._certsRepo = certsRepo;

        this._mainRouter.get("/certs", this._certsGetAllPublicKey.bind(this));

        this._mainRouter.get(
            "/certs/:participantId",
            this._certsGetCertificate.bind(this)
        );
    }

    get MainRouter(): express.Router {
        return this._mainRouter;
    }

    private async _certsGetAllPublicKey(
        req: express.Request,
        res: express.Response
    ): Promise<void> {
        this._logger.debug("Received request to Fetch All Public Keys");

        try {
            const publicKeys = await this._certsRepo.getAllPublicKeys();

            res.status(200).send(publicKeys);
        } catch (error: unknown) {
            this._logger.error(`Error getting all Public Keys: ${(error as Error).message}`);
            res.status(404).json({
                status: "error",
                msg: (error as Error).message
            });
        }
    }

    private async _certsGetCertificate(
        req: express.Request,
        res: express.Response
    ): Promise<void> {
        this._logger.debug("Received request to Fetch Public Certificate");
        const participantId = req.params.participantId;

        try {
            const cert = await this._certsRepo.getCertificateByParticipantId(participantId);
            if(!cert) {
                throw new Error(`No certificate found for participantId: ${participantId}`);
            }

            if(!cert.approved) {
                throw new Error(`Certificate not approved yet for participantId: ${participantId}`);
            }

            res.status(200).send(cert);
        } catch (error: unknown) {
            this._logger.error(`Error getting certificate: ${(error as Error).message}`);
            res.status(404).json({
                status: "error",
                msg: (error as Error).message
            });
        }
    }
}
