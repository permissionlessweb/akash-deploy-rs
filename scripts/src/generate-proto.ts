/**
 * Akash Console API — Proto Generator
 *
 * Converts Zod schemas from console-api-schemas.ts into proto3 service
 * definitions using @globalart/zod-to-proto.
 *
 * Output: ../proto/console/<service>.proto
 *
 * Usage:
 *   cd scripts && npm install && npm run generate
 */

import { zodToProtobufService } from "@globalart/zod-to-proto";
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

import {
  // Auth
  ListApiKeysResponseSchema,
  ApiKeyVisibleResponseSchema,
  ApiKeyHiddenResponseSchema,
  CreateApiKeyRequestSchema,
  UpdateApiKeyRequestSchema,
  FindApiKeyParamsSchema,
  // Bid
  ListBidsQuerySchema,
  ListBidsResponseSchema,
  // Certificate
  CreateCertificateResponseSchema,
  // Deployment
  GetDeploymentParamsSchema,
  GetDeploymentResponseSchema,
  CreateDeploymentRequestSchema,
  CreateDeploymentResponseSchema,
  CloseDeploymentParamsSchema,
  CloseDeploymentResponseSchema,
  DepositDeploymentRequestSchema,
  DepositDeploymentResponseSchema,
  UpdateDeploymentRequestSchema,
  UpdateDeploymentResponseSchema,
  ListDeploymentsQuerySchema,
  ListDeploymentsResponseSchema,
  ListWithResourcesParamsSchema,
  ListWithResourcesResponseSchema,
  GetDeploymentByOwnerDseqParamsSchema,
  GetDeploymentByOwnerDseqResponseSchema,
  GetWeeklyDeploymentCostResponseSchema,
  // Lease
  CreateLeaseRequestSchema,
  LeaseStatusResponseSchema,
  // Deployment Settings
  GetDeploymentSettingParamsSchema,
  DeploymentSettingSchema,
  UpdateDeploymentSettingRequestSchema,
  // Provider
  ProviderParamsSchema,
  ProviderListQuerySchema,
  ProviderListResponseSchema,
  ProviderResponseSchema,
  ProviderActiveLeasesGraphDataParamsSchema,
  ProviderActiveLeasesGraphDataResponseSchema,
  // JWT
  GetJwtTokenRequestSchema,
  GetJwtTokenResponseSchema,
  // Network
  GetNodesParamsSchema,
  GetNodesResponseSchema,
  // Pricing
  PricingSpecsSchema,
  PricingResponseSchema,
  // Address
  GetAddressParamsSchema,
  GetAddressResponseSchema,
  GetAddressTransactionsParamsSchema,
  GetAddressTransactionsResponseSchema,
  // Schema count for reporting
  ALL_SCHEMAS,
} from "./console-api-schemas.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PROTO_OUT_DIR = join(__dirname, "../../proto/console");

function writeProto(filename: string, content: string): void {
  mkdirSync(PROTO_OUT_DIR, { recursive: true });
  const outPath = join(PROTO_OUT_DIR, filename);
  writeFileSync(outPath, content, "utf8");
  console.log(`  ✓ wrote ${outPath}`);
}

// ---------------------------------------------------------------------------
// Service definitions
//
// Each entry maps to one .proto file.  Services use the explicit
// ServiceDefinition[] format: { name, methods: [{ name, request, response }] }
// — this is the format @globalart/zod-to-proto expects without needing to
// introspect z.function() schema internals.
// ---------------------------------------------------------------------------

const services: Array<{
  filename: string;
  packageName: string;
  methods: Array<{ name: string; request: z.ZodTypeAny; response: z.ZodTypeAny }>;
  serviceName: string;
}> = [
  // -------------------------------------------------------------------
  // Deployment service
  // -------------------------------------------------------------------
  {
    filename: "deployment.proto",
    packageName: "console.deployment",
    serviceName: "DeploymentService",
    methods: [
      { name: "ListDeployments",          request: ListDeploymentsQuerySchema,              response: ListDeploymentsResponseSchema },
      { name: "GetDeployment",            request: GetDeploymentParamsSchema,               response: GetDeploymentResponseSchema },
      { name: "GetDeploymentByOwnerDseq", request: GetDeploymentByOwnerDseqParamsSchema,    response: GetDeploymentByOwnerDseqResponseSchema },
      { name: "CreateDeployment",         request: CreateDeploymentRequestSchema,           response: CreateDeploymentResponseSchema },
      { name: "UpdateDeployment",         request: UpdateDeploymentRequestSchema,           response: UpdateDeploymentResponseSchema },
      { name: "CloseDeployment",          request: CloseDeploymentParamsSchema,             response: CloseDeploymentResponseSchema },
      { name: "DepositDeployment",        request: DepositDeploymentRequestSchema,          response: DepositDeploymentResponseSchema },
      { name: "ListWithResources",        request: ListWithResourcesParamsSchema,           response: ListWithResourcesResponseSchema },
      { name: "GetWeeklyDeploymentCost",  request: z.object({}),                           response: GetWeeklyDeploymentCostResponseSchema },
    ],
  },

  // -------------------------------------------------------------------
  // Lease service
  // -------------------------------------------------------------------
  {
    filename: "lease.proto",
    packageName: "console.lease",
    serviceName: "LeaseService",
    methods: [
      { name: "CreateLease",    request: CreateLeaseRequestSchema, response: z.object({ success: z.boolean() }) },
      {
        name: "GetLeaseStatus",
        request: z.object({ dseq: z.string(), gseq: z.number(), oseq: z.number(), provider: z.string() }),
        response: LeaseStatusResponseSchema,
      },
    ],
  },

  // -------------------------------------------------------------------
  // Deployment settings service
  // -------------------------------------------------------------------
  {
    filename: "deployment_settings.proto",
    packageName: "console.deployment.settings",
    serviceName: "DeploymentSettingsService",
    methods: [
      { name: "GetDeploymentSetting",    request: GetDeploymentSettingParamsSchema,    response: DeploymentSettingSchema },
      { name: "UpdateDeploymentSetting", request: UpdateDeploymentSettingRequestSchema, response: DeploymentSettingSchema },
    ],
  },

  // -------------------------------------------------------------------
  // Bid service
  // -------------------------------------------------------------------
  {
    filename: "bid.proto",
    packageName: "console.bid",
    serviceName: "BidService",
    methods: [
      { name: "ListBids", request: ListBidsQuerySchema, response: ListBidsResponseSchema },
    ],
  },

  // -------------------------------------------------------------------
  // Certificate service
  // -------------------------------------------------------------------
  {
    filename: "certificate.proto",
    packageName: "console.certificate",
    serviceName: "CertificateService",
    methods: [
      { name: "CreateCertificate", request: z.object({}), response: CreateCertificateResponseSchema },
    ],
  },

  // -------------------------------------------------------------------
  // Provider service
  // -------------------------------------------------------------------
  {
    filename: "provider.proto",
    packageName: "console.provider",
    serviceName: "ProviderService",
    methods: [
      { name: "ListProviders",                 request: ProviderListQuerySchema,                       response: z.object({ providers: ProviderListResponseSchema }) },
      { name: "GetProvider",                   request: ProviderParamsSchema,                          response: ProviderResponseSchema },
      { name: "GetProviderActiveLeasesGraph",  request: ProviderActiveLeasesGraphDataParamsSchema,     response: ProviderActiveLeasesGraphDataResponseSchema },
      { name: "GetJwtToken",                   request: GetJwtTokenRequestSchema,                      response: GetJwtTokenResponseSchema },
    ],
  },

  // -------------------------------------------------------------------
  // Network service
  // -------------------------------------------------------------------
  {
    filename: "network.proto",
    packageName: "console.network",
    serviceName: "NetworkService",
    methods: [
      { name: "GetNodes", request: GetNodesParamsSchema, response: z.object({ nodes: GetNodesResponseSchema }) },
    ],
  },

  // -------------------------------------------------------------------
  // Pricing service
  // -------------------------------------------------------------------
  {
    filename: "pricing.proto",
    packageName: "console.pricing",
    serviceName: "PricingService",
    methods: [
      {
        name: "GetPricing",
        request: z.object({ specs: z.array(PricingSpecsSchema) }),
        response: z.object({ results: PricingResponseSchema }),
      },
    ],
  },

  // -------------------------------------------------------------------
  // Auth / API Keys service
  // -------------------------------------------------------------------
  {
    filename: "auth.proto",
    packageName: "console.auth",
    serviceName: "AuthService",
    methods: [
      { name: "ListApiKeys",  request: z.object({}),                response: ListApiKeysResponseSchema },
      { name: "CreateApiKey", request: CreateApiKeyRequestSchema,   response: ApiKeyVisibleResponseSchema },
      { name: "UpdateApiKey", request: UpdateApiKeyRequestSchema,   response: ApiKeyHiddenResponseSchema },
      { name: "DeleteApiKey", request: FindApiKeyParamsSchema,      response: z.object({ success: z.boolean() }) },
      { name: "GetApiKey",    request: FindApiKeyParamsSchema,      response: ApiKeyHiddenResponseSchema },
    ],
  },

  // -------------------------------------------------------------------
  // Address service
  // -------------------------------------------------------------------
  {
    filename: "address.proto",
    packageName: "console.address",
    serviceName: "AddressService",
    methods: [
      { name: "GetAddress",             request: GetAddressParamsSchema,             response: GetAddressResponseSchema },
      { name: "GetAddressTransactions", request: GetAddressTransactionsParamsSchema, response: GetAddressTransactionsResponseSchema },
    ],
  },
];

// ---------------------------------------------------------------------------
// Generate
// ---------------------------------------------------------------------------

console.log("Akash Console API — Proto Generator");
console.log(`Schema registry: ${Object.keys(ALL_SCHEMAS).length} schemas`);
console.log(`Output dir:      ${PROTO_OUT_DIR}`);
console.log("");

let errorCount = 0;

for (const { filename, packageName, serviceName, methods } of services) {
  try {
    const proto = zodToProtobufService({
      packageName,
      services: [{ name: serviceName, methods }],
    });
    writeProto(filename, proto);
  } catch (err) {
    console.error(`  ✗ ${filename}: ${(err as Error).message}`);
    errorCount++;
  }
}

console.log("");
if (errorCount === 0) {
  console.log(`Done — ${services.length} proto files written to ${PROTO_OUT_DIR}`);
} else {
  console.log(`Done with ${errorCount} error(s). Check output above.`);
  process.exit(1);
}
