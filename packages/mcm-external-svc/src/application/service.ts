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

// eslint-disable-next-line @typescript-eslint/no-var-requires
const packageJSON = require("../../package.json");
import path from "path";
import express, {Express} from "express";
import process from "process";
import {ExpressRoutes} from "./routes";
import {ConsoleLogger, ILogger, LogLevel} from "@mojaloop/logging-bc-public-types-lib";
import {KafkaLogger} from "@mojaloop/logging-bc-client-lib";

import {IConfigurationClient} from "@mojaloop/platform-configuration-bc-public-types-lib";
import {IMessageProducer} from "@mojaloop/platform-shared-lib-messaging-types-lib";
import {MLKafkaJsonProducer} from "@mojaloop/platform-shared-lib-nodejs-kafka-client-lib";
import * as util from "util";
import {Server} from "net";

import {MongoCertsRepo} from "@mojaloop/cert-management-bc-implementations-lib";
import {CertificateAggregate} from "@mojaloop/cert-management-bc-domain-lib";
import {ICertRepo} from "@mojaloop/cert-management-bc-domain-lib";

const APP_NAME = "mcm-external-svc";
const BC_NAME = "cert-management-bc";
const APP_VERSION = packageJSON.version;
const PRODUCTION_MODE = process.env["PRODUCTION_MODE"] || false;
const LOG_LEVEL: LogLevel = process.env["LOG_LEVEL"] as LogLevel || LogLevel.DEBUG;

const SVC_DEFAULT_HTTP_PORT = 3220;

const KAFKA_URL = process.env["KAFKA_URL"] || "localhost:9092";
const KAFKA_LOGS_TOPIC = process.env["KAFKA_LOGS_TOPIC"] || "logs";

const SERVICE_START_TIMEOUT_MS= (process.env["SERVICE_START_TIMEOUT_MS"] && parseInt(process.env["SERVICE_START_TIMEOUT_MS"])) || 60_000;
const CERT_DIR = process.env["CERT_DIR"] || path.join(__dirname, "../certs");

const DB_NAME_CERTIFICATES = "certificates";

const MONGO_URL = process.env["MONGO_URL"] || "mongodb://root:mongoDbPas42@localhost:27017/";

const kafkaProducerOptions = {
    kafkaBrokerList: KAFKA_URL
};


let globalLogger: ILogger;


export class Service {
    static logger: ILogger;
    static certsRepo: ICertRepo;
    static app: Express;
    static expressServer: Server;
    static messageProducer: IMessageProducer;
    static configClient: IConfigurationClient;
    static startupTimer: NodeJS.Timeout;
    static certificateAggregate: CertificateAggregate;

    static async start(
        logger?: ILogger,
        messageProducer?: IMessageProducer,
        certsRepo?: ICertRepo,
        // configProvider?: IConfigProvider,
    ): Promise<void> {
        console.log(`Service starting with PID: ${process.pid}`);

        this.startupTimer = setTimeout(()=>{
            throw new Error("Service start timed-out");
        }, SERVICE_START_TIMEOUT_MS);

        if (!logger) {
            logger = new KafkaLogger(
                BC_NAME,
                APP_NAME,
                APP_VERSION,
                kafkaProducerOptions,
                KAFKA_LOGS_TOPIC,
                LOG_LEVEL
            );

            try{
                await (logger as KafkaLogger).init();
            }catch(e){
                globalLogger = logger = new ConsoleLogger();
                logger.error("KafkaLogger init error: ", (e as Error).message);
                process.exit(999);
            }
        }
        globalLogger = this.logger = logger;

        if(!certsRepo){
			certsRepo = new MongoCertsRepo(this.logger, MONGO_URL, DB_NAME_CERTIFICATES);
            await certsRepo.init();
            this.logger.info("MongoDB Certificates Repo Initialized");
		}

        this.certsRepo = certsRepo;
        if (!messageProducer) {
            const producerLogger = logger.createChild("producerLogger");
            producerLogger.setLogLevel(LogLevel.INFO);
            messageProducer = new MLKafkaJsonProducer(kafkaProducerOptions, producerLogger);
            await messageProducer.connect();
        }
        this.messageProducer = messageProducer;

        this.certificateAggregate = new CertificateAggregate(
            this.configClient,
            this.messageProducer,
            this.logger,
            this.certsRepo,
            CERT_DIR
        );

        // await this.certificateAggregate.init();


        await this.setupExpress();

        // remove startup timeout
        clearTimeout(this.startupTimer);
    }

    static setupExpress(): Promise<void> {
        return new Promise<void>(resolve => {
            this.app = express();
            this.app.use(express.json()); // for parsing application/json
            this.app.use(express.urlencoded({extended: true})); // for parsing application/x-www-form-urlencoded

            const routes = new ExpressRoutes(this.configClient, this.certificateAggregate, this.logger, this.certsRepo);

            // Add health and metrics http routes - before others (to avoid authZ middleware)
            this.app.get("/health", (_req: express.Request, res: express.Response) => {
                return res.send({ status: "OK" });
            });

            // app routes
            this.app.use("/", routes.MainRouter);

            this.app.use((_req, res) => {
                // catch all
                res.send(404);
            });

            let portNum = SVC_DEFAULT_HTTP_PORT;
            if (process.env["SVC_HTTP_PORT"] && !isNaN(parseInt(process.env["SVC_HTTP_PORT"]))) {
                portNum = parseInt(process.env["SVC_HTTP_PORT"]);
            }

            this.expressServer = this.app.listen(portNum, () => {
                this.logger.info(`🚀 Server ready at port: ${portNum}`);
                this.logger.info(`Certificate Management service v: ${APP_VERSION} started`);
                resolve();
            });
        });
    }

    static async stop() {
        if (this.expressServer){
            const closeExpress = util.promisify(this.expressServer.close.bind(this.expressServer));
            await closeExpress();
        }
        if (this.messageProducer) await this.messageProducer.destroy();
        if (this.logger && this.logger instanceof KafkaLogger) await this.logger.destroy();
    }
}


/**
 * process termination and cleanup
 */

async function _handle_int_and_term_signals(signal: NodeJS.Signals): Promise<void> {
    console.info(`Service - ${signal} received - cleaning up...`);
    let clean_exit = false;
    setTimeout(() => {
        clean_exit || process.exit(99);
    }, 5000);

    // call graceful stop routine
    await Service.stop();

    clean_exit = true;
    process.exit();
}

//catches ctrl+c event
process.on("SIGINT", _handle_int_and_term_signals);
//catches program termination event
process.on("SIGTERM", _handle_int_and_term_signals);

//do something when app is closing
process.on("exit", async () => {
    globalLogger.info("Microservice - exiting...");
});
process.on("uncaughtException", (err: Error) => {
    globalLogger.error(err);
    console.log("UncaughtException - EXITING...");
    process.exit(999);
});

