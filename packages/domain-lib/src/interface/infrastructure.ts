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
 - Si Thu Myo <sithu.myo@thisaworks.com.

 --------------
 **/

"use strict";

import {ICertificate, ICertificateRequest, IPublicKeyInfo} from "@mojaloop/cert-management-bc-public-types-lib";

export interface ICertRepo {
    init(): Promise<void>;
    destroy(): Promise<void>;

    getAllCertificates(): Promise<ICertificate[]>;
    getAllPublicKeys(): Promise<IPublicKeyInfo[]>;

    getCertificateByParticipantId(participantId: string): Promise<ICertificate | null>;
    getCertificateByObjectId(objectId: string): Promise<ICertificate | null>;
    getCertificateRequests(): Promise<ICertificateRequest[]>;
    getPendingCertificateRequests(): Promise<ICertificateRequest[]>;
    getCertificateRequestsByParticipantId(participantId: string): Promise<ICertificateRequest | null>;
    getCertificateRequestsByParticipantIds(participantIds: string[]): Promise<ICertificateRequest[]>;

    addCertificateRequest(certificate: ICertificate): Promise<void>;
    updateCertificate(certificate: ICertificate): Promise<void>;
    deleteCertificate(participantId: string): Promise<void>;

    approveCertificate(certificateId: string, approvedBy: string): Promise<void>;
    bulkApproveCertificates(certificateIds: string[], approvedBy: string): Promise<void>;

    rejectCertificate(certificateId: string, rejectedBy: string): Promise<void>;
    bulkRejectCertificates(certificateIds: string[], rejectedBy: string): Promise<void>;

    deleteCertificateRequest(certificateId: string, participantId: string): Promise<void>;
    bulkDeleteCertificateRequests(certificateIds: string[]): Promise<void>;

    isAllCertificatesUniqueParticipants(certificateIds: string[]): Promise<boolean>;
}
