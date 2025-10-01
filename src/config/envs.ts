import 'dotenv/config';
import * as joi from 'joi';

interface OidcClient {
  id: string;
  secret: string;
  origins: string[];
} 

interface EnvVars {
  PORT: number;
  HOST: string;
  
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
  OIDC_CLIENTS?: string;
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
    OIDC_CLIENTS: joi.string().optional(),
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

/* ======== Parse y validación de OIDC_CLIENTS ======== */
const clientsRaw: unknown = (() => {
  try {
    return JSON.parse(envVars.OIDC_CLIENTS ?? '[]');
  } catch (e) {
    throw new Error(`Invalid JSON in OIDC_CLIENTS: ${e}`);
  }
})();

const clientsSchema = joi.array().items(
  joi.object({
    id: joi.string().min(1).required(),
    secret: joi.string().min(1).required(),
    origins: joi.array().items(joi.string().uri()).min(1).required(),
  })
).min(1);

const { error: clientsErr, value: clients } = clientsSchema.validate(clientsRaw);
if (clientsErr) throw new Error(`OIDC_CLIENTS validation error: ${clientsErr.message}`);

/* ======== Helpers ======== */
const normalizeOrigin = (o: string) => o.replace(/\/+$/, ''); // quita / final
const uniq = <T,>(arr: T[]) => Array.from(new Set(arr));

export const GatewayEnvs = {
  host: envVars.HOST,
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
  client: clients as OidcClient[],
};

export const FrontEnvs = {
   frontendServers: uniq(
    (clients as OidcClient[]).flatMap(c => c.origins.map(normalizeOrigin))
  ),
};

export const PvtEnvs = {
  PvtBeApiServer: envVars.PVT_BE_API_SERVER + '/api/v1',
  PvtBackendApiServer: envVars.PVT_BACKEND_API_SERVER + '/api',
  PvtHashSecret: envVars.PVT_HASH_SECRET,
};
