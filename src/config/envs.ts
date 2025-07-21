import 'dotenv/config';
import * as joi from 'joi';

interface EnvVars {
  PORT: number;

  NATS_SERVERS: string[];

  FRONTENDS_SERVERS: string[];

  PVT_BE_API_SERVER: string;
  PVT_BACKEND_API_SERVER: string;
  PVT_HASH_SECRET: string;

  DB_PASSWORD: string;
  DB_DATABASE: string;
  DB_HOST: string;
  DB_PORT: number;
  DB_USERNAME: string;

  // Keycloak configuration
  KEYCLOAK_URL?: string;
  KEYCLOAK_REALM?: string;
  KEYCLOAK_CLIENT_ID?: string;
  KEYCLOAK_CLIENT_SECRET?: string;
  KEYCLOAK_COOKIE_KEY?: string;
  KEYCLOAK_USE_NEST_LOGGER?: boolean;
}

const envsSchema = joi
  .object({
    PORT: joi.number().required(),

    NATS_SERVERS: joi.array().items(joi.string()).required(),
    FRONTENDS_SERVERS: joi.array().items(joi.string()).required(),

    PVT_API_SERVER: joi.string(),
    PVT_HASH_SECRET: joi.string(),

    DB_PASSWORD: joi.string().required(),
    DB_DATABASE: joi.string().required(),
    DB_HOST: joi.string().required(),
    DB_PORT: joi.number().required(),
    DB_USERNAME: joi.string().required(),

    // Keycloak configuration
    KEYCLOAK_URL: joi.string().uri().optional(),
    KEYCLOAK_REALM: joi.string().optional(),
    KEYCLOAK_CLIENT_ID: joi.string().optional(),
    KEYCLOAK_CLIENT_SECRET: joi.string().optional(),
    KEYCLOAK_COOKIE_KEY: joi.string().optional(),
    KEYCLOAK_USE_NEST_LOGGER: joi.boolean().optional(),
  })
  .unknown(true);

const { error, value } = envsSchema.validate({
  ...process.env,
  NATS_SERVERS: process.env.NATS_SERVERS?.split(','),
  FRONTENDS_SERVERS: process.env.FRONTENDS_SERVERS?.split(','),
});

if (error) {
  throw new Error(`Config validation error: ${error.message}`);
}

const envVars: EnvVars = value;

export const PortEnvs = {
  port: envVars.PORT,
};

export const NastEnvs = {
  natsServers: envVars.NATS_SERVERS,
};

export const DbEnvs = {
  dbPassword: envVars.DB_PASSWORD,
  dbDatabase: envVars.DB_DATABASE,
  dbHost: envVars.DB_HOST,
  dbPort: envVars.DB_PORT,
  dbUsername: envVars.DB_USERNAME,
};

export const KeycloakEnvs = {
  authServerUrl: envVars.KEYCLOAK_URL,
  realm: envVars.KEYCLOAK_REALM,
  clientId: envVars.KEYCLOAK_CLIENT_ID,
  secret: envVars.KEYCLOAK_CLIENT_SECRET,
};

export const FrontEnvs = {
  frontendServers: envVars.FRONTENDS_SERVERS,
};

export const PvtEnvs = {
  PvtBeApiServer: envVars.PVT_BE_API_SERVER + '/api/v1',
  PvtBackendApiServer: envVars.PVT_BACKEND_API_SERVER + '/api',
  PvtHashSecret: envVars.PVT_HASH_SECRET,
};
