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

import express from "express";
import { ILogger } from "@mojaloop/logging-bc-public-types-lib";
import { IConfigurationClient } from "@mojaloop/platform-configuration-bc-public-types-lib";

import {
    CertificateAggregate,
    CertificatesPrivileges,
    CertificateRequestState,
    CertType,
    ICertRepo,
    ICertificate,
    ICertificateInfo,
    BulkApprovalRequestResults,
} from "@mojaloop/cert-management-bc-domain-lib";

import multer from "multer";
import {
    CallSecurityContext,
    ForbiddenError,
    IAuthorizationClient,
    ITokenHelper,
} from "@mojaloop/security-bc-public-types-lib";
import { Certificate } from "pkijs";
import * as asn1js from "asn1js";

// Extend express request to include our security fields
declare module "express-serve-static-core" {
    export interface Request {
        securityContext: null | CallSecurityContext;
    }
}

export class ExpressRoutes {
    private _logger: ILogger;
    private _tokenHelper: ITokenHelper;
    private _configClient: IConfigurationClient;
    private _certsAgg: CertificateAggregate;
    private _certsRepo: ICertRepo;

    private _mainRouter = express.Router();
    private _authorizationClient: IAuthorizationClient;

    constructor(
        configClient: IConfigurationClient,
        certsAgg: CertificateAggregate,
        logger: ILogger,
        tokenHelper: ITokenHelper,
        certsRepo: ICertRepo,
        authorizationClient: IAuthorizationClient
    ) {
        this._configClient = configClient;
        this._logger = logger;
        this._tokenHelper = tokenHelper;
        this._certsAgg = certsAgg;
        this._certsRepo = certsRepo;
        this._authorizationClient = authorizationClient;

        const storage = multer.memoryStorage();
        const uploadfile = multer({ storage: storage });

        // inject authentication - all request below this require a valid token
        this._mainRouter.use(this._authenticationMiddleware.bind(this));

        this._mainRouter.get(
            "/certs/requests",
            this._getCertificateRequests.bind(this)
        );

        this._mainRouter.get(
            "/certs/requests/pending",
            this._getPendingCertificateRequests.bind(this)
        );

        this._mainRouter.get(
            "/certs/:participantId",
            this._getCertificateByParticipantId.bind(this)
        );

        this._mainRouter.get(
            "/certs/download/:certificateId",
            this._downloadPublicKey.bind(this)
        );

        this._mainRouter.post(
            "/certs/file",
            uploadfile.single("cert"),
            this._addFileCertificateRequest.bind(this)
        );

        this._mainRouter.post(
            "/certs/:_id/approve",
            this._approveCertificateRequest.bind(this)
        );

        this._mainRouter.post(
            "/certs/bulkapprove",
            this._bulkApproveAddingCertificateRequest.bind(this)
        );

        this._mainRouter.post(
            "/certs/:_id/reject/:participantId",
            this._rejectCertificateRequest.bind(this)
        );

        this._mainRouter.post(
            "/certs/bulkreject",
            this._bulkRejectCertificateRequest.bind(this)
        );
    }


    get MainRouter(): express.Router {
        return this._mainRouter;
    }

    private async _authenticationMiddleware(
        req: express.Request,
        res: express.Response,
        next: express.NextFunction
    ) {
        const authorizationHeader = req.headers["authorization"];

        if (!authorizationHeader) return res.sendStatus(401);

        const bearer = authorizationHeader.trim().split(" ");
        if (bearer.length != 2) {
            return res.sendStatus(401);
        }

        const bearerToken = bearer[1];
        const callSecCtx:  CallSecurityContext | null = await this._tokenHelper.getCallSecurityContextFromAccessToken(bearerToken);

        if(!callSecCtx){
            return res.sendStatus(401);
        }

        req.securityContext = callSecCtx;
        return next();
    }

    private _validateCertFilename(cert_id: string, cert_file: Express.Multer.File): boolean {
        // filename should be cert_id.cer
        const allowed_ext = ["cer", "pem", "crt"];
        const filename = cert_file.originalname;
        const filename_parts = filename.split(".");
        if (filename_parts.length != 2) {
            return false;
        }
        if (filename_parts[0] != cert_id) {
            return false;
        }
        if (!allowed_ext.includes(filename_parts[1])) {
            return false;
        }
        return true;
    }

    private async _getCertificateByParticipantId(
        req: express.Request,
        res: express.Response
    ): Promise<void> {
        const participantId = req.params.participantId;
        this._logger.info(`Fetch Public Certificate [${participantId}]`);

        try {
            this._enforcePrivilege(req.securityContext!, CertificatesPrivileges.VIEW_CERTIFICATES);
            const cert = await this._certsRepo.getCertificateByParticipantId(participantId);
            res.status(200).send(cert);
        } catch (error: unknown) {
            this._logger.error(`Error getting certificate: ${(error as Error).message}`);
            res.status(404).json({
                status: "error",
                msg: (error as Error).message
            });
        }
    }

    private async _getCertificateRequests(
        req: express.Request,
        res: express.Response
    ): Promise<void> {
        this._logger.info("Fetch Certificate Requests: ", req.query.participantId);

        try {
            this._enforcePrivilege(req.securityContext!, CertificatesPrivileges.VIEW_CERTIFICATES);
            const participantId = req.query.participantId as string;
            if(participantId){
                const certRequest = await this._certsRepo.getCertificateRequestsByParticipantId(participantId);
                if(certRequest === null){
                    res.status(200).send([]);
                    return;
                }
                res.status(200).send([certRequest]);
                return;
            }

            const certRequests = await this._certsRepo.getCertificateRequests();
            res.status(200).send(certRequests);
        } catch (error: unknown) {

            this._logger.error(`Error getting certificate requests: ${(error as Error).message}`);
            res.status(500).json({
                status: "error",
                msg: (error as Error).message
            });
        }
    }

    private async _getPendingCertificateRequests(
        req: express.Request,
        res: express.Response
    ): Promise<void> {
        this._logger.info("Fetch Pending Certificate Requests");

        try {
            const certRequests = await this._certsRepo.getPendingCertificateRequests();
            res.status(200).send(certRequests);
        } catch (error: unknown) {
            this._logger.error(`Error getting pending certificate requests: ${(error as Error).message}`);
            res.status(500).json({
                status: "error",
                msg: (error as Error).message
            });
        }
    }

    private async _downloadPublicKey(
        req: express.Request,
        res: express.Response
    ): Promise<void> {
        this._logger.debug("Received request to download public key");

        const certificateId = req.params.certificateId;
        if (!certificateId) {
            res.status(400).json({ error: "certificateId is required" });
            return;
        }

        try {
            this._enforcePrivilege(req.securityContext!, CertificatesPrivileges.VIEW_CERTIFICATES);
            const cert = await this._certsRepo.getCertificateByObjectId(certificateId);
            if (!cert) {
                res.status(404).json({ error: "Certificate not found" });
                return;
            }

            const fileName = `${cert.participantId}.pem`;
            res.setHeader("Content-Type", "application/x-pem-file");
            res.setHeader("Content-Disposition", `attachment; filename=${fileName}`);
            res.send(cert.publicKey);
        } catch (error: unknown) {
            this._logger.error(`Error downloading certificate: ${(error as Error).message}`);
            res.status(500).json({ error: "Internal server error" });
        }
    }

    private async _addFileCertificateRequest(
        req: express.Request,
        res: express.Response
    ): Promise<void> {
        this._logger.debug("Received request to Store cert uploaded as file");

        const participantId = req.body.participantId ?? null;
        if(!participantId){
            res.status(400).json({ status: "error", msg: "participantId is required" });
            return;
        }

        try {
            this._enforcePrivilege(req.securityContext!, CertificatesPrivileges.CREATE_CERTIFICATE_REQUEST);
            if (!req.file) {
                this._logger.debug("No file uploaded");
                res.status(422).json({ status: "error", msg: "No file uploaded" });
                return;
            }

            if(this._validateCertFilename(participantId, req.file) == false) {
                this._logger.debug(`Invalid file uploaded. use '${participantId}.(cer/crt/pem)' as filename. ` );
                res.status(400).json({ status: "error", msg: `Invalid file uploaded. use '${participantId}.(cer/crt/pem)' as filename. ` });
                return;
            }

            const cert = req.file.buffer.toString();

            if (!this._validateCertificateData(cert)) {
                res.status(400).json({ status: "error", msg: "Invalid certificate data" });
                return;
            }

            const pkijsCert = this._parseCertificate(cert);
            if (!pkijsCert) {
                res.status(400).json({ status: "error", msg: "Invalid certificate data" });
                return;
            }

            // Extract certificate info
            const certInfo: ICertificateInfo = {
                subject:  pkijsCert.subject.typesAndValues.map((tv) => `${this.getCertCommonName(tv.type)}: ${tv.value.valueBlock.value}`).join(", "),
                issuer : pkijsCert.issuer.typesAndValues.map((tv) => `${this.getCertCommonName(tv.type)}: ${tv.value.valueBlock.value}`).join(", "),
                validFrom : pkijsCert.notBefore.value.toString(),
                validTo : pkijsCert.notAfter.value.toString(),
                serialNumber : pkijsCert.serialNumber.valueBlock.toString(),
                publicKeyAlgorithm : this.getCertCommonName(pkijsCert.subjectPublicKeyInfo.algorithm.algorithmId),
                signatureAlgorithm : this.getCertCommonName(pkijsCert.signatureAlgorithm.algorithmId),
                extensions : {},
            };
            const publicKeyInfo = pkijsCert.subjectPublicKeyInfo;
            // Assuming publicKeyInfo is obtained as shown in the previous steps
            const spkiBuffer = publicKeyInfo.toSchema().toBER(); // Serializes the public key to DER-encoded ArrayBuffer

            // Convert the public key to PEM format
            const publicKeyPem = this.convertToPem(spkiBuffer, "PUBLIC KEY");

            const newCertificate: ICertificate = {
                _id: null,
                participantId: participantId,
                type: CertType.PUBLIC,
                cert: cert,
                publicKey: publicKeyPem,
                certInfo: certInfo,
                description: null,
                createdBy: req.securityContext!.username!,
                createdDate: new Date(),
                requestState: CertificateRequestState.CREATED,
                approved: false,
                approvedBy: null,
                approvedDate: null,
                rejected: false,
                rejectedBy: null,
                rejectedDate: null,
                lastUpdated: Date.now()
            };

            await this._certsRepo.addCertificateRequest(newCertificate);
            this._logger.debug("Certificate stored successfully");
            res.status(200).send();

        } catch (error: unknown) {
            this._logger.error(`Error storing certificate: ${(error as Error).message}`);
            res.status(500).json({
                status: "error",
                msg: (error as Error).message
            });
        }
    }

    private async _approveCertificateRequest(
        req: express.Request,
        res: express.Response
    ): Promise<void> {
        this._logger.debug("Received request to approve adding certificate");

        const certificateId = req.params._id ?? null;
        if(!certificateId){
            res.status(400).json({ status: "error", msg: "certificateId is required" });
            return;
        }

        try {
            this._enforcePrivilege(req.securityContext!, CertificatesPrivileges.APPROVE_CERTIFICATE_REQUEST);
            await this._certsRepo.approveCertificate(certificateId, req.securityContext!.username!);
            res.status(200).send();
        } catch (error: unknown) {
            this._logger.error(`Error approving adding certificate: ${(error as Error).message}`);
            res.status(500).json({
                status: "error",
                msg: (error as Error).message
            });
        }
    }

    private async _bulkApproveAddingCertificateRequest(
        req: express.Request,
        res: express.Response
    ): Promise<void> {
        this._logger.debug("Received to approve bulk certificate");

        const certificateIds = req.body.certificateIds ?? null;
        if(!certificateIds) {
            res.status(400).json({ status: "error", msg: "certificateIds is required" });
            return;
        }

        try {
            this._enforcePrivilege(req.securityContext!, CertificatesPrivileges.APPROVE_CERTIFICATE_REQUEST);
             const messages: BulkApprovalRequestResults[] = [];

            for (const certificateId of certificateIds) {
                try{
                    await this._certsRepo.approveCertificate(certificateId, req.securityContext!.username!);
                     messages.push({
                         reqId: certificateId,
                         status: "success",
                         message: `Successfully approved request id: ${certificateId}.`,
                     });
                }catch (error: unknown) {
                    messages.push({
                        reqId: certificateId,
                        status: "error",
                        message: `Failed to approve request Id: ${certificateId}. ${(error as Error).message}`,
                    });
                }
            }

            res.status(200).send(messages);
        } catch (error: unknown) {
            this._logger.error(`Error bulk approving certificate requests: ${(error as Error).message}`);
            res.status(500).json({
                status: "error",
                msg: (error as Error).message
            });
        }
    }

    private async _rejectCertificateRequest(
        req: express.Request,
        res: express.Response
    ): Promise<void> {
        this._logger.debug("Received request to reject adding certificate");

        const certificateId = req.params._id ?? null;
        const participantId = req.params.participantId ?? null;

        if(!certificateId){
            res.status(400).json({ status: "error", msg: "certificate's _id is required" });
            return;
        }

        if(!participantId){
            res.status(400).json({ status: "error", msg: "participantId is required" });
            return;
        }

        try {
            this._enforcePrivilege(req.securityContext!, CertificatesPrivileges.REJECT_CERTIFICATE_REQUEST);
            await this._certsRepo.rejectCertificate(certificateId, req.securityContext!.username!);
            res.status(200).send();

        } catch (error: unknown) {
            this._logger.error(`Error approving adding certificate: ${(error as Error).message}`);
            res.status(500).json({
                status: "error",
                msg: (error as Error).message
            });
        }
    }

    private async _bulkRejectCertificateRequest(
        req: express.Request,
        res: express.Response
    ): Promise<void> {
        this._logger.debug("Received bulk reject certificate requests");
        this._enforcePrivilege(req.securityContext!, CertificatesPrivileges.REJECT_CERTIFICATE_REQUEST);

        const certificateIds = req.body.certificateIds ?? null;
        if(!certificateIds) {
            res.status(400).json({ status: "error", msg: "certificateIds is required" });
            return;
        }

        try {
            const messages: BulkApprovalRequestResults[] = [];
            for (const certificateId of certificateIds) {
                try{
                    await this._certsRepo.rejectCertificate(certificateId, req.securityContext!.username!);
                    messages.push({
                        reqId: certificateId,
                        status: "success",
                        message: `Successfully rejected request id: ${certificateId}.`,
                    });
                }catch (error: unknown) {
                    messages.push({
                        reqId: certificateId,
                        status: "error",
                        message: `Failed to reject request Id: ${certificateId}. ${(error as Error).message}`,
                    });
                }
            }

            res.status(200).send(messages);
        } catch (error: unknown) {
            this._logger.error(`Error bulk rejecting certificate requests: ${(error as Error).message}`);
            res.status(500).json({
                status: "error",
                msg: (error as Error).message
            });
        }
    }

    private _validateCertificateData(pem: string): boolean {
        try {
            const parsedCert = this._parseCertificate(pem);
            if (!parsedCert) {
                return false;
            }
            return true;
        } catch (error: unknown) {
            this._logger.error(`Error parsing certificate: ${(error as Error).message}`);
            return false;
        }
    }


    private _parseCertificate(pem: string): Certificate | null  {
        // Convert PEM to ArrayBuffer,
        // removing header, footer and line breaks
        const b64 = pem.replace(/(-----(BEGIN|END) [^-]+-----|[\n\r])/g, "");
        const binaryString = atob(b64);
        const bytes = new Uint8Array(binaryString.length);

        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }

        // Parse the certificate
        const asn1 = asn1js.fromBER(bytes.buffer);
        if (asn1.offset === -1) {
            this._logger.error("Error cannot parse certificate content");
            throw new Error("Error cannot parse certificate content");
        }

        // Try catch block to handle parsing errors?
        const certificate = new Certificate({ schema: asn1.result });

        return certificate;
    }

    private convertToPem(buffer: ArrayBuffer, type: string): string {
        const base64 = Buffer.from(buffer).toString("base64");
        const formattedBase64 = base64.replace(/(.{64})/g, "$1\n");

        const pem = `-----BEGIN ${type}-----\n${formattedBase64}\n-----END ${type}-----\n`;

        return pem;
    }

    private getCertCommonName(oid: string): string {
        const oidMap: Record<string, string> = {
            "2.5.4.6": "Country Name",
            "2.5.4.8": "State or Province Name",
            "2.5.4.7": "Locality",
            "2.5.4.10": "Organization Name",
            "2.5.4.11": "Organizational Unit Name",
            "2.5.4.3": "Common Name",
            "1.2.840.113549.1.1.1": "RSA Encryption",
            "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
            "1.2.840.10040.4.1": "DSA",
            "1.2.840.10045.2.1": "EC Public Key",
            // Algorithm Identifiers
            "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
            "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
        };

        return oidMap[oid]|| oid; // return Return the OID itself if a mapping is not found
    }

    private _enforcePrivilege(secCtx: CallSecurityContext, privilegeId: string): void {
        for (const roleId of secCtx.platformRoleIds) {
            if (this._authorizationClient.roleHasPrivilege(roleId, privilegeId)) {
                return;
            }
        }
        const error = new ForbiddenError(`Required privilege "${privilegeId}" not held by caller`);
        this._logger.isWarnEnabled() && this._logger.warn(error.message);
        throw error;
    }

}
