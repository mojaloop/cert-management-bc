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

import { Collection, Document, MongoClient, ObjectId, WithId } from "mongodb";
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
    ICertificateRequest
} from "@mojaloop/cert-management-bc-domain-lib";

export class MongoCertsRepo implements ICertRepo {
    private readonly _logger: ILogger;
    private readonly _connectionString: string;
    private readonly _dbName;
    private readonly _collectionName = "certificates";
    private readonly _requestsCollectionName = "certificateApproval";
    private mongoClient: MongoClient;
    private certsCollection: Collection;
    private approvalsCollection: Collection;

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

            this.approvalsCollection = this.mongoClient
                .db(this._dbName)
                .collection(this._requestsCollectionName);

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

    async getAllCertificates(): Promise<ICertificate[]> {
        const certs = await this.certsCollection
            .find()
            .toArray()
            .catch((e: unknown) => {
                this._logger.error(
                    `Unable to get all certificates: ${(e as Error).message}`
                );
                throw new UnableToGetCertError(
                    "Unable to get all certificates"
                );
            });

        return certs.map((cert) => this.mapToCert(cert));
    }

    async getCertificateByObjectId(
        objectId: string
    ): Promise<ICertificate | null> {
        const cert = await this.certsCollection
            .findOne({ _id: new ObjectId(objectId) })
            .catch((e: unknown) => {
                this._logger.error(
                    `Unable to get certificate by object id: ${(e as Error).message}`
                );
                throw new UnableToGetCertError(
                    "Unable to get certificate by object id"
                );
            });

        if (!cert) {
            return null;
        }
        return this.mapToCert(cert);
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

    async getCertificateRequests(): Promise<ICertificateRequest[]> {
        const certs = await this.approvalsCollection
            .find()
            .sort({ createdDate: 1 })
            .toArray()
            .catch((e: unknown) => {
                this._logger.error(
                    `Unable to get certificate requests: ${(e as Error).message}`
                );
                throw new UnableToGetCertError(
                    "Unable to get certificate requests"
                );
            });

        return certs.map((cert) => this.mapToCertRequest(cert));
    }

    async getCertificateRequestsByParticipantId(
        participantId: string
    ): Promise<ICertificateRequest | null> {
        const cert = await this.approvalsCollection
            .findOne({ participantId: participantId })
            .catch((e: unknown) => {
                this._logger.error(
                    `Unable to get certificate requests by participant id: ${(e as Error).message}`
                );
                throw new UnableToGetCertError(
                    "Unable to get certificate requests by participant id"
                );
            });

        if (!cert) {
            return null;
        }

        return this.mapToCertRequest(cert);
    }

    async getCertificateRequestsByParticipantIds(
        participantIds: string[]
    ): Promise<ICertificateRequest[]> {
        const certs = await this.approvalsCollection
            .find({ participantId: { $in: participantIds }, approved: false })
            .toArray()
            .catch((e: unknown) => {
                this._logger.error(
                    `Unable to get certificate requests by participant ids: ${participantIds} - ${(e as Error).message}`
                );
                throw new UnableToGetCertError(
                    "Unable to get certificate requests by participant ids"
                );
            });
        this._logger.debug(
            `Got certificate requests by participant ids: ${participantIds}`, certs
        );

        return certs.map((cert) => this.mapToCertRequest(cert));
    }

    async addCertificateRequest(certificate: ICertificate): Promise<void> {
        const certToAdd: any = { ...certificate };
        certToAdd._id = new ObjectId();

        let participantRequsts  = await this.approvalsCollection.findOne(
            { participantId: certificate.participantId },
        );

        if (!participantRequsts) {
            // New Participant
            participantRequsts = {
                _id: new ObjectId(),
                participantId: certificate.participantId,
                participantCertificateUploadRequests: [certToAdd]
            };
            await this.approvalsCollection.insertOne(participantRequsts).catch((e: unknown) => {
                this._logger.error(
                    `Unable to insert certificate: ${(e as Error).message}`
                );
                throw new UnableToAddCertError("Unable to insert certificate");
            });
        } else {
            // Existing Participant and add the new certificate request
            participantRequsts.participantCertificateUploadRequests.push(certToAdd);
            await this.approvalsCollection.updateOne(
                { participantId: certificate.participantId },
                { $set: participantRequsts }
            ).catch((e: unknown) => {
                this._logger.error(
                    `Unable to insert certificate: ${(e as Error).message}`
                );
                throw new UnableToAddCertError("Unable to insert certificate");
            });
        }
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

    async approveCertificate(
        certificateId: string,
        approvedBy: string
    ): Promise<void> {
        const certObjectId = new ObjectId(certificateId);
        try{
            // Find the approval request containing the certificate request
            const approvalDocument = await this.approvalsCollection.findOne({
                "participantCertificateUploadRequests._id": certObjectId
            });

            if (!approvalDocument) {
                throw new Error("Approval Document not found.");
            }

             // Extract the specific certificate from request list
            const certificate = approvalDocument.participantCertificateUploadRequests.find(
                (cert : ICertificate) => cert._id == certificateId
            );

             if (!certificate) {
                throw new Error("Certificate request not found within the approval document.");
            }

            const participantId = approvalDocument.participantId;

            // Move the certificate request to the approved collection
            await this.moveToApprovedCollection(certificate, participantId, approvedBy);

        } catch (e: unknown) {
            this._logger.error(`Unable to approve certificate: ${(e as Error).message}`);
            throw new UnableToUpdateCertError("Unable to approve certificate");
        }

    }

    async bulkApproveCertificates(
        certificateIds: string[],
        approvedBy: string
    ): Promise<void> {
        const certObjectIds = certificateIds.map((id) => new ObjectId(id));
        const pipeline = [
            {
                $match: {
                    "participantCertificateUploadRequests._id": { $in: certObjectIds }
                }
            },
            {
                $project: {
                    participantId: 1,
                    participantCertificateUploadRequests: {
                        $filter: {
                            input: "$participantCertificateUploadRequests",
                            as: "request",
                            cond: { $in: ["$$request._id", certObjectIds] }
                        }
                    }
                }
            }
        ];

        const approvalDocuments = await this.approvalsCollection.aggregate(pipeline).toArray();

        this._logger.info("approvalDocuments:", approvalDocuments);

        if (approvalDocuments.length === 0) {
            throw new Error("Approval Document not found.");
        }

        const participantIds = approvalDocuments.map((doc) => doc.participantId);
        this._logger.info("participantIds:", participantIds);

        // Extract the specific certificates from request list
        const certificates = approvalDocuments.flatMap(doc => doc.participantCertificateUploadRequests);

        this._logger.info("certificates:", certificates);

        if (certificates.length === 0) {
            throw new Error("Certificate request not found within the approval document.");
        }

        // Move the certificate requests to the approved collection
        await this.moveMultipleCertsToApprovedCollection(certificates, participantIds, approvedBy);

    }

    async deleteCertificateRequest(certificateId: string, participantId: string): Promise<void> {
        // Remove from cert request
        await this.approvalsCollection.updateOne(
            { participantId: participantId },
            { $pull: { participantCertificateUploadRequests: { _id: new ObjectId(certificateId) } } }
        ).catch((e: unknown) => {
            this._logger.error(
                `Unable to delete certificate request: ${(e as Error).message}`
            );
            throw new UnableToDeleteCertError(
                "Unable to delete certificate request"
            );
        });
    }

    async isAllCertificatesUniqueParticipants(certificateIds: string[]): Promise<boolean> {
        // get participantIds from the certificateIds
        const certObjectIds = certificateIds.map((id) => new ObjectId(id));
        const participantIds = await this.certsCollection.find(
            { _id: { $in: certObjectIds } },
            { projection: { participantId: 1 } })
            .toArray()
            .then((certs) => certs.map((cert) => cert.participantId));

        // check if all participantIds are unique
        return new Set(participantIds).size === participantIds.length;
    }


    private mapToCert(cert: WithId<Document>): ICertificate {
        const certMapped: any = {
            ...cert,
            _id: cert._id.toHexString(),
        };
        return certMapped;
    }

    private mapToCertRequest(certRequest: WithId<Document>): ICertificateRequest {
        const sortRequests = certRequest.participantCertificateUploadRequests.sort((a: ICertificate, b: ICertificate) => {
            return b.createdDate.getTime() - a.createdDate.getTime();
        });

        const certRequestMapped: any = {
            ...certRequest,
            participantCertificateUploadRequests: sortRequests,
            _id: certRequest._id.toHexString(),
        };
        return certRequestMapped;
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

    private async moveToApprovedCollection(
        certificate: ICertificate,
        participantId: string,
        approvedBy: string
    ): Promise<void> {

        await this.certsCollection.deleteOne({ participantId: participantId });

        let _id;
        if(certificate._id === null) {
            _id = new ObjectId();
        } else {
         _id = new ObjectId(certificate._id);
        }

        await this.certsCollection.insertOne({
            ...certificate,
            _id,
            approved: true,
            approvedDate: new Date(),
            approvedBy: approvedBy
        });


        // Remove from approvalsCollection
        await this.approvalsCollection.updateOne(
            { participantId: participantId },
            { $pull: { participantCertificateUploadRequests: { _id: certificate._id } } }
        );
    }

    private async moveMultipleCertsToApprovedCollection(
        certificates: ICertificate[],
        participantIds: string[],
        approvedBy: string
    ): Promise<void> {

        const validCertIds = certificates
            .map((cert) => cert._id)
            .filter((id): id is string => id !== null)
            .map((id) => new ObjectId(id));

        await this.certsCollection.deleteMany({ participantId: { $in: participantIds } });

        const certsToInsert = certificates.map((cert) => {
            let _id;
            if(cert._id === null) {
                _id = new ObjectId();
            } else {
                _id = new ObjectId(cert._id);
            }
            return {
                ...cert,
                _id,
                approved: true,
                approvedDate: new Date(),
                approvedBy: approvedBy,
            };
        });

        await this.certsCollection.insertMany(certsToInsert);

        await this.approvalsCollection.updateMany(
            { participantId: { $in: participantIds } },
            { $pull: { participantCertificateUploadRequests: { _id: { $in: validCertIds } } } } as any
        );
    }


}
