/**
 License
 --------------
 Copyright © 2021 Mojaloop Foundation

 The Mojaloop files are made available by the Mojaloop Foundation under the Apache License, Version 2.0 (the "License") and you may not use these files except in compliance with the License.

 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, the Mojaloop files are distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 Contributors
 --------------
 This is the official list (alphabetical ordering) of the Mojaloop project contributors for this file.
 Names of the original copyright holders (individuals or organizations)
 should be listed with a '' in the first column. People who have
 contributed from an organization can be listed under the organization
 that actually holds the copyright for their contributions (see the
 Gates Foundation organization for an example). Those individuals should have
 their names indented and be marked with a '-'. Email address can be added
 optionally within square brackets <email>.

 * Gates Foundation
 - Name Surname <name.surname@gatesfoundation.com>

 * ThitsaWorks
 - Si Thu Myo <sithu.myo@thitsaworks>

 --------------
 **/

"use strict";

import { Collection, Document, MongoClient, WithId } from "mongodb";
import { ILogger } from "@mojaloop/logging-bc-public-types-lib";
import {
    CertAlreadyExistsError,
    UnableToCloseDatabaseConnectionError,
    UnableToDeleteCertError,
    UnableToAddCertError,
    UnableToInitCertRegistryError,
    UnableToUpdateCertError,
    UnableToGetCertError,
    CertNotFoundError,
} from "../errors";
import {
    ICertRepo,
    ICertificate,
} from "@mojaloop/cert-management-bc-domain-lib";

export class MongoCertsRepo implements ICertRepo {
    private readonly _logger: ILogger;
    private readonly _connectionString: string;
    private readonly _dbName;
    private readonly _collectionName = "certificates";
    private mongoClient: MongoClient;
    private certsCollection: Collection;

    constructor(logger: ILogger, connectionString: string, dbName: string) {
        this._logger = logger.createChild(this.constructor.name);
        this._connectionString = connectionString;
        this._dbName = dbName;
    }

    async init(): Promise<void> {
        try {
            this.mongoClient = new MongoClient(this._connectionString);
            this.mongoClient.connect();
            this.certsCollection = this.mongoClient
                .db(this._dbName)
                .collection(this._collectionName);
        } catch (e: unknown) {
            this._logger.error(
                `Unable to connect to the database: ${(e as Error).message}`
            );
            throw new UnableToInitCertRegistryError(
                "Unable to connect to certificates DB"
            );
        }
    }

    async destroy(): Promise<void> {
        try {
            await this.mongoClient.close();
        } catch (e: unknown) {
            this._logger.error(
                `Unable to close the database connection: ${
                    (e as Error).message
                }`
            );
            throw new UnableToCloseDatabaseConnectionError(
                "Unable to close certificates DB connection"
            );
        }
    }

    async addCertificate(certificate: ICertificate): Promise<void> {
        const certToAdd = { ...certificate };
        if (certToAdd.participantId) {
            await this.checkIfCertExists(certificate);
        }

        await this.certsCollection.insertOne(certToAdd).catch((e: unknown) => {
            this._logger.error(
                `Unable to insert certificate: ${(e as Error).message}`
            );
            throw new UnableToAddCertError("Unable to insert certificate");
        });
    }

    async updateCertificate(certificate: ICertificate): Promise<void> {
        const existingCert = await this.getCertificateByParticipantId(
            certificate.participantId
        );

        if (!existingCert || !existingCert.participantId) {
            throw new CertNotFoundError("Certificate not found");
        }

        await this.certsCollection
            .updateOne(
                { participantId: certificate.participantId },
                { $set: certificate }
            )

            .catch((e: unknown) => {
                this._logger.error(
                    `Unable to insert certificate: ${(e as Error).message}`
                );
                throw new UnableToUpdateCertError(
                    "Unable to update certificate"
                );
            });
    }

    async deleteCertificate(participantId: string): Promise<void> {
        const deleteResult = await this.certsCollection
            .deleteOne({ participantId })

            .catch((e: unknown) => {
                this._logger.error(
                    `Unable to delete certificate: ${(e as Error).message}`
                );
                throw new UnableToDeleteCertError(
                    "Unable to delete certificate"
                );
            });

        if (deleteResult.deletedCount == 1) {
            return;
        } else {
            throw new CertNotFoundError("Certificate not found");
        }
    }

    async getCertificateByParticipantId(
        participantId: string
    ): Promise<ICertificate | null> {
        const cert = await this.certsCollection
            .findOne({ participantId: participantId })

            .catch((e: unknown) => {
                this._logger.error(
                    `Unable to get certificate by id: ${(e as Error).message}`
                );
                throw new UnableToGetCertError(
                    "Unable to get certificate by id"
                );
            });

        if (!cert) {
            return null;
        }

        return this.mapToCert(cert);
    }

    async approveCertificate(
        participantId: string,
        approvedBy: string
    ): Promise<void> {
        const existingCert = await this.getCertificateByParticipantId(
            participantId
        );

        if (!existingCert || !existingCert.participantId) {
            throw new CertNotFoundError("Certificate not found");
        }

        await this.certsCollection
            .updateOne(
                { participantId: participantId },
                {
                    $set: {
                        approved: true,
                        approvedBy: approvedBy,
                        approvedDate: new Date(),
                    },
                }
            )

            .catch((e: unknown) => {
                this._logger.error(
                    `Unable to approve certificate: ${(e as Error).message}`
                );
                throw new UnableToUpdateCertError(
                    "Unable to approve certificate"
                );
            });
    }

    // async rejectCertificate(
    //     participantId: string,
    //     approvedBy: string
    // ): Promise<void> {
    //     const existingCert = await this.getCertificateByParticipantId(
    //         participantId
    //     );
    //
    //     if (!existingCert || !existingCert.participantId) {
    //         throw new CertNotFoundError("Certificate not found");
    //     }
    //
    //     await this.certsCollection
    //         .updateOne(
    //             { participantId: participantId },
    //             {
    //                 $set: {
    //                     approved: false,
    //                     approvedBy: approvedBy,
    //                     approvedDate: new Date(),
    //                 },
    //             }
    //         )
    //         .catch((e: unknown) => {
    //             this._logger.error(
    //                 `Unable to reject certificate: ${(e as Error).message}`
    //             );
    //             throw new UnableToUpdateCertError(
    //                 "Unable to reject certificate"
    //             );
    //         });
    // }
    //



    // We don't need this for now
    // async getCertificates(): Promise<ICertificate[]> {
    //     const certs = await this.certsCollection
    //         .find()
    //         .toArray()
    //         .catch((e: unknown) => {
    //             this._logger.error(
    //                 `Unable to get certificates: ${(e as Error).message}`
    //             );
    //             throw new UnableToGetCertError("Unable to get certificates");
    //         });
    //
    //     const mappedCerts = [];
    //
    //     for (const cert of certs) {
    //         mappedCerts.push(this.mapToCert(cert));
    //     }
    //
    //     return mappedCerts;
    // }

    private mapToCert(cert: WithId<Document>): ICertificate {
        const certMapped: ICertificate = {
            participantId: cert.participantId ?? null,
            type: cert.type ?? null,
            cert: cert.cert ?? null,
            description: cert.description ?? null,
            createdBy: cert.createdBy ?? null,
            createdDate: cert.createdDate ?? null,
            approved: cert.approved ?? null,
            approvedBy: cert.approvedBy ?? null,
            approvedDate: cert.approvedDate ?? null,
            lastUpdated: cert.lastUpdated ?? null,
        };
        return certMapped;
    }

    private async checkIfCertExists(certificate: ICertificate) {
        const certAlreadyPresent: WithId<Document> | null =
            await this.certsCollection
                .findOne({
                    participantId: certificate.participantId,
                })

                .catch((e: unknown) => {
                    this._logger.error(
                        `Unable to add certificate: ${(e as Error).message}`
                    );
                    throw new UnableToGetCertError("Unable to add certificate");
                });

        if (certAlreadyPresent) {
            throw new CertAlreadyExistsError("Certificate already exists");
        }
    }

}
