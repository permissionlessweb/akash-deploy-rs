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

  // Billing / Wallet / Stripe
  WalletResponseOutputSchema, WalletListResponseOutputSchema, StartTrialRequestInputSchema,
  WalletSettingsResponseSchema, CreateWalletSettingsRequestSchema,
  SetupIntentResponseSchema, PaymentMethodsResponseSchema, PaymentMethodMarkAsDefaultInputSchema,
  ConfirmPaymentRequestSchema, ConfirmPaymentResponseSchema,
  ApplyCouponRequestSchema, ApplyCouponResponseSchema,
  CustomerTransactionsQuerySchema, CustomerTransactionsResponseSchema,
  ValidatePaymentMethodRequestSchema, ValidatePaymentMethodResponseSchema,
  RemovePaymentMethodParamsSchema, UpdateCustomerOrganizationRequestSchema,
  StripePricesResponseSchema, GetBalancesQuerySchema, GetBalancesResponseOutputSchema,
  SignTxRequestInputSchema, SignTxResponseOutputSchema,
  GetUsageHistoryQuerySchema, UsageHistoryResponseSchema, UsageHistoryStatsResponseSchema,
  // User
  GetUserResponseOutputSchema, CheckUsernameParamsSchema, CheckUsernameResponseSchema,
  UpdateUserSettingsRequestSchema, VerifyEmailRequestSchema,
  // Dashboard
  DashboardDataResponseSchema, GraphDataParamsSchema, GraphDataResponseSchema,
  NetworkCapacityResponseSchema, MarketDataParamsSchema, MarketDataResponseSchema,
  BmeDashboardDataResponseSchema, BmeStatusHistoryResponseSchema,
  LeasesDurationParamsSchema, LeasesDurationResponseSchema,
  // GPU
  ListGpuQuerySchema, ListGpuResponseSchema, ListGpuModelsResponseSchema,
  GpuBreakdownQuerySchema, GpuBreakdownResponseSchema, GpuPricesResponseSchema,
  // Templates
  GetTemplatesListResponseSchema, GetTemplateByIdParamsSchema, GetTemplateByIdResponseSchema,
  // Transactions
  ListTransactionsQuerySchema, ListTransactionsResponseSchema,
  GetTransactionByHashParamsSchema, GetTransactionByHashResponseSchema,
  // Blocks
  ListBlocksQuerySchema, ListBlocksResponseSchema, GetBlockByHeightParamsSchema, GetBlockByHeightResponseSchema,
  GetPredictedBlockDateParamsSchema, GetPredictedBlockDateResponseSchema,
  GetPredictedDateHeightParamsSchema, GetPredictedDateHeightResponseSchema,
  // Validators
  GetValidatorListResponseSchema, GetValidatorByAddressParamsSchema, GetValidatorByAddressResponseSchema,
  // Proposals
  GetProposalListResponseSchema, GetProposalByIdParamsSchema, GetProposalByIdResponseSchema,
  // Provider (additional)
  AuditorListResponseSchema, CreateJwtTokenRequestSchema, CreateJwtTokenResponseSchema,
  ProviderDashboardParamsSchema, ProviderDashboardResponseSchema,
  ProviderDeploymentsParamsSchema, ProviderDeploymentsResponseSchema,
  ProviderEarningsParamsSchema, ProviderEarningsResponseSchema,
  ProviderGraphDataParamsSchema, ProviderGraphDataResponseSchema,
  ProviderRegionsResponseSchema, ProviderVersionsResponseSchema, ProviderAttributesSchemaResponseSchema,
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


  // -------------------------------------------------------------------
  // Billing / Wallet service
  // -------------------------------------------------------------------
  {
    filename: "billing.proto",
    packageName: "console.billing",
    serviceName: "BillingService",
    methods: [
      { name: "GetWallet",            request: z.object({}),                      response: WalletResponseOutputSchema },
      { name: "GetWalletList",        request: z.object({}),                      response: WalletListResponseOutputSchema },
      { name: "StartTrial",           request: StartTrialRequestInputSchema,      response: WalletResponseOutputSchema },
      { name: "GetWalletSettings",    request: z.object({}),                      response: WalletSettingsResponseSchema },
      { name: "UpdateWalletSettings", request: CreateWalletSettingsRequestSchema, response: WalletSettingsResponseSchema },
      { name: "GetBalances",          request: GetBalancesQuerySchema,            response: GetBalancesResponseOutputSchema },
      { name: "SignAndBroadcastTx",   request: SignTxRequestInputSchema,          response: SignTxResponseOutputSchema },
      { name: "GetUsageHistory",      request: GetUsageHistoryQuerySchema,        response: z.object({ data: UsageHistoryResponseSchema }) },
      { name: "GetUsageHistoryStats", request: GetUsageHistoryQuerySchema,        response: UsageHistoryStatsResponseSchema },
    ],
  },

  // -------------------------------------------------------------------
  // Stripe / Payment service
  // -------------------------------------------------------------------
  {
    filename: "stripe.proto",
    packageName: "console.stripe",
    serviceName: "StripeService",
    methods: [
      { name: "SetupPaymentMethod",      request: z.object({}),                          response: SetupIntentResponseSchema },
      { name: "ListPaymentMethods",      request: z.object({}),                          response: PaymentMethodsResponseSchema },
      { name: "SetDefaultPaymentMethod", request: PaymentMethodMarkAsDefaultInputSchema, response: z.object({ success: z.boolean() }) },
      { name: "RemovePaymentMethod",     request: RemovePaymentMethodParamsSchema,       response: z.object({ success: z.boolean() }) },
      { name: "ValidatePaymentMethod",   request: ValidatePaymentMethodRequestSchema,    response: ValidatePaymentMethodResponseSchema },
      { name: "ConfirmPayment",          request: ConfirmPaymentRequestSchema,           response: ConfirmPaymentResponseSchema },
      { name: "ApplyCoupon",             request: ApplyCouponRequestSchema,              response: ApplyCouponResponseSchema },
      { name: "ListTransactions",        request: CustomerTransactionsQuerySchema,       response: CustomerTransactionsResponseSchema },
      { name: "GetPrices",              request: z.object({}),                          response: StripePricesResponseSchema },
      { name: "UpdateOrganization",      request: UpdateCustomerOrganizationRequestSchema, response: z.object({ success: z.boolean() }) },
    ],
  },

  // -------------------------------------------------------------------
  // User service
  // -------------------------------------------------------------------
  {
    filename: "user.proto",
    packageName: "console.user",
    serviceName: "UserService",
    methods: [
      { name: "GetCurrentUser",            request: z.object({}),               response: GetUserResponseOutputSchema },
      { name: "GetUserByUsername",          request: CheckUsernameParamsSchema,  response: GetUserResponseOutputSchema },
      { name: "CheckUsernameAvailability",  request: CheckUsernameParamsSchema,  response: CheckUsernameResponseSchema },
      { name: "UpdateUserSettings",        request: UpdateUserSettingsRequestSchema, response: GetUserResponseOutputSchema },
      { name: "VerifyEmail",               request: VerifyEmailRequestSchema,   response: z.object({ success: z.boolean() }) },
    ],
  },

  // -------------------------------------------------------------------
  // Dashboard / Analytics service
  // -------------------------------------------------------------------
  {
    filename: "dashboard.proto",
    packageName: "console.dashboard",
    serviceName: "DashboardService",
    methods: [
      { name: "GetDashboardData",    request: z.object({}),           response: DashboardDataResponseSchema },
      { name: "GetGraphData",        request: GraphDataParamsSchema,  response: GraphDataResponseSchema },
      { name: "GetNetworkCapacity",  request: z.object({}),           response: NetworkCapacityResponseSchema },
      { name: "GetMarketData",       request: MarketDataParamsSchema, response: MarketDataResponseSchema },
      { name: "GetBmeDashboardData", request: z.object({}),           response: BmeDashboardDataResponseSchema },
      { name: "GetBmeStatusHistory", request: z.object({}),           response: z.object({ data: BmeStatusHistoryResponseSchema }) },
      { name: "GetLeasesDuration",   request: LeasesDurationParamsSchema, response: LeasesDurationResponseSchema },
    ],
  },

  // -------------------------------------------------------------------
  // GPU service
  // -------------------------------------------------------------------
  {
    filename: "gpu.proto",
    packageName: "console.gpu",
    serviceName: "GpuService",
    methods: [
      { name: "ListGpus",        request: ListGpuQuerySchema,      response: ListGpuResponseSchema },
      { name: "ListGpuModels",   request: z.object({}),            response: z.object({ models: ListGpuModelsResponseSchema }) },
      { name: "GetGpuBreakdown", request: GpuBreakdownQuerySchema, response: z.object({ data: GpuBreakdownResponseSchema }) },
      { name: "GetGpuPrices",    request: z.object({}),            response: GpuPricesResponseSchema },
    ],
  },

  // -------------------------------------------------------------------
  // Template service
  // -------------------------------------------------------------------
  {
    filename: "template.proto",
    packageName: "console.template",
    serviceName: "TemplateService",
    methods: [
      { name: "ListTemplates", request: z.object({}),               response: GetTemplatesListResponseSchema },
      { name: "GetTemplate",   request: GetTemplateByIdParamsSchema, response: GetTemplateByIdResponseSchema },
    ],
  },

  // -------------------------------------------------------------------
  // Transaction service (on-chain)
  // -------------------------------------------------------------------
  {
    filename: "transaction.proto",
    packageName: "console.transaction",
    serviceName: "TransactionService",
    methods: [
      { name: "ListTransactions",     request: ListTransactionsQuerySchema,      response: z.object({ data: ListTransactionsResponseSchema }) },
      { name: "GetTransactionByHash", request: GetTransactionByHashParamsSchema, response: GetTransactionByHashResponseSchema },
    ],
  },

  // -------------------------------------------------------------------
  // Block service
  // -------------------------------------------------------------------
  {
    filename: "block.proto",
    packageName: "console.block",
    serviceName: "BlockService",
    methods: [
      { name: "ListBlocks",             request: ListBlocksQuerySchema,             response: z.object({ data: ListBlocksResponseSchema }) },
      { name: "GetBlockByHeight",       request: GetBlockByHeightParamsSchema,      response: GetBlockByHeightResponseSchema },
      { name: "GetPredictedBlockDate",  request: GetPredictedBlockDateParamsSchema, response: GetPredictedBlockDateResponseSchema },
      { name: "GetPredictedDateHeight", request: GetPredictedDateHeightParamsSchema, response: GetPredictedDateHeightResponseSchema },
    ],
  },

  // -------------------------------------------------------------------
  // Validator service
  // -------------------------------------------------------------------
  {
    filename: "validator.proto",
    packageName: "console.validator",
    serviceName: "ValidatorService",
    methods: [
      { name: "ListValidators",        request: z.object({}),                      response: z.object({ data: GetValidatorListResponseSchema }) },
      { name: "GetValidatorByAddress", request: GetValidatorByAddressParamsSchema, response: GetValidatorByAddressResponseSchema },
    ],
  },

  // -------------------------------------------------------------------
  // Proposal service
  // -------------------------------------------------------------------
  {
    filename: "proposal.proto",
    packageName: "console.proposal",
    serviceName: "ProposalService",
    methods: [
      { name: "ListProposals",   request: z.object({}),                  response: z.object({ data: GetProposalListResponseSchema }) },
      { name: "GetProposalById", request: GetProposalByIdParamsSchema,   response: GetProposalByIdResponseSchema },
    ],
  },

  // -------------------------------------------------------------------
  // Provider (additional endpoints)
  // -------------------------------------------------------------------
  {
    filename: "provider_extended.proto",
    packageName: "console.provider.extended",
    serviceName: "ProviderExtendedService",
    methods: [
      { name: "ListAuditors",              request: z.object({}),                   response: z.object({ data: AuditorListResponseSchema }) },
      { name: "CreateJwtToken",            request: CreateJwtTokenRequestSchema,    response: CreateJwtTokenResponseSchema },
      { name: "GetProviderDashboard",      request: ProviderDashboardParamsSchema,  response: ProviderDashboardResponseSchema },
      { name: "GetProviderDeployments",    request: ProviderDeploymentsParamsSchema, response: ProviderDeploymentsResponseSchema },
      { name: "GetProviderEarnings",       request: ProviderEarningsParamsSchema,   response: ProviderEarningsResponseSchema },
      { name: "GetProviderGraphData",      request: ProviderGraphDataParamsSchema,  response: ProviderGraphDataResponseSchema },
      { name: "GetProviderRegions",        request: z.object({}),                   response: z.object({ data: ProviderRegionsResponseSchema }) },
      { name: "GetProviderVersions",       request: z.object({}),                   response: ProviderVersionsResponseSchema },
      { name: "GetProviderAttributesSchema", request: z.object({}),                 response: ProviderAttributesSchemaResponseSchema },
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
