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

 * Gates Foundation
 - Name Surname <name.surname@gatesfoundation.com>

 * ThitsaWorks
 - Si Thu Myo <sithu.myo@thitsaworks.com>

 --------------
 ******/

"use strict";
export enum CertificatesPrivileges {
    VIEW_CERTIFICATES = "CERTIFICATES_VIEW_CERTIFICATES",
    CREATE_CERTIFICATE_REQUEST = "CERTIFICATES_CREATE_REQUEST",
    APPROVE_CERTIFICATE_REQUEST = "CERTIFICATES_APPROVE_REQUEST",
    REJECT_CERTIFICATE_REQUEST = "CERTIFICATES_REJECT_REQUEST",
}

export const CertificatesPrivilegesDefinition = [
    {
        privId: CertificatesPrivileges.VIEW_CERTIFICATES,
        labelName: "View Certificates",
        description: "Allows for the retrieval of any certificates"
    },
    {
        privId: CertificatesPrivileges.CREATE_CERTIFICATE_REQUEST,
        labelName: "Create Certificate Request",
        description: "Allows for the creation of a new certificate request"
    },
    {
        privId: CertificatesPrivileges.APPROVE_CERTIFICATE_REQUEST,
        labelName: "Approve Certificate Request",
        description: "Allows for the approval of a certificate request"
    },
    {
        privId: CertificatesPrivileges.REJECT_CERTIFICATE_REQUEST,
        labelName: "Reject Certificate Request",
        description: "Allows for the rejection of a certificate request"
    }
];


